use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use certon::{FileStorage, Storage};

struct BlockingGate {
    release: Option<Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    active: Arc<AtomicBool>,
}

impl BlockingGate {
    fn enter() -> Self {
        let active = Arc::new(AtomicBool::new(false));
        let worker_active = active.clone();
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            worker_active.store(true, Ordering::SeqCst);
            entered.send(()).unwrap();
            let _ = released.recv();
            worker_active.store(false, Ordering::SeqCst);
        });
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        Self {
            release: Some(release),
            task: Some(task),
            active,
        }
    }

    fn signal(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for BlockingGate {
    fn drop(&mut self) {
        // An assertion failure must not strand a blocking worker at shutdown.
        self.signal();
    }
}

fn independent_unlock(cancel_first_await: bool) {
    // Drop runtimes before removing their storage directory on any failure.
    let directory = tempfile::tempdir().unwrap();
    let runtime_a = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let runtime_b = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let storage = FileStorage::new(directory.path());
    runtime_a.block_on(async {
        storage.lock("a").await.unwrap();
        storage.lock("b").await.unwrap();
    });
    let mut gate = {
        let _entered = runtime_a.enter();
        BlockingGate::enter()
    };
    let mut unlock_a = Some(Box::pin(storage.unlock("a")));
    {
        let _entered = runtime_a.enter();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            unlock_a.as_mut().unwrap().as_mut().poll(&mut context),
            Poll::Pending
        ));
    }
    // B has independent, idle blocking capacity. It must not wait for A's
    // pool merely to remove its different handle from the shared registry.
    assert_eq!(
        runtime_b.block_on(async { tokio::task::spawn_blocking(|| 42).await.unwrap() }),
        42
    );
    runtime_b.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), storage.unlock("b"))
            .await
            .expect("independent key B was blocked by A's queued close")
            .unwrap();
    });
    assert!(
        gate.active.load(Ordering::SeqCst),
        "B must complete while A's close remains queued"
    );
    let released_b = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("locks/b.lock"))
        .unwrap();
    released_b.try_lock().unwrap();
    drop(released_b);

    if cancel_first_await {
        drop(unlock_a.take());
    }
    let pending_a = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("locks/a.lock"))
        .unwrap();
    assert!(
        matches!(pending_a.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "the queued close must retain the actual OS lock even if its await was cancelled"
    );
    assert!(gate.active.load(Ordering::SeqCst));
    gate.signal();
    runtime_a.block_on(async {
        gate.task.take().unwrap().await.unwrap();
        if let Some(unlock) = unlock_a.take() {
            unlock.await.unwrap();
        }
        // The detached close was submitted before this single-thread barrier.
        tokio::task::spawn_blocking(|| ()).await.unwrap();
    });
    pending_a.try_lock().unwrap();
}

#[test]
fn an_independent_runtime_can_unlock_while_another_close_is_queued() {
    independent_unlock(false);
}

#[test]
fn cancelling_a_queued_unlock_still_closes_its_owned_os_handle() {
    independent_unlock(true);
}
