use std::future::Future;
use std::sync::mpsc::{self, Sender};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use certon::{FileStorage, Storage};

struct BlockingGate {
    release: Option<Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl BlockingGate {
    fn enter() -> Self {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = entered_tx.send(());
            let _ = release_rx.recv();
        });
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Self {
            release: Some(release_tx),
            task: Some(task),
        }
    }

    fn signal(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }

    async fn release(mut self) {
        self.signal();
        self.task.take().unwrap().await.unwrap();
    }
}

impl Drop for BlockingGate {
    fn drop(&mut self) {
        // Failing assertions must not strand a blocked closure at runtime exit.
        self.signal();
    }
}

fn cancel_public_store(writer_finished_before_cancel: bool) {
    let directory = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(directory.path());
    let key = "certificates/ca/example.com/_certon/resource.v1.key";
    let destination = directory.path().join(key);
    let parent = destination.parent().unwrap();
    std::fs::create_dir_all(parent).unwrap();
    std::fs::write(&destination, b"complete old resource").unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let first_gate = BlockingGate::enter();
        let mut store = Box::pin(storage.store(key, b"complete replacement private resource"));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(store.as_mut().poll(&mut context), Poll::Pending));
        first_gate.release().await;
        let second_gate = BlockingGate::enter();
        // mkdir has completed. Unix has one extra chmod await before write.
        #[cfg(unix)]
        let writer_gate = {
            assert!(matches!(store.as_mut().poll(&mut context), Poll::Pending));
            second_gate.release().await;
            BlockingGate::enter()
        };
        #[cfg(not(unix))]
        let writer_gate = second_gate;
        assert!(matches!(store.as_mut().poll(&mut context), Poll::Pending));

        if writer_finished_before_cancel {
            writer_gate.release().await;
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert_eq!(
                std::fs::read_dir(parent).unwrap().count(),
                2,
                "the completed temporary write must await its rename owner"
            );
            drop(store);
        } else {
            drop(store);
            writer_gate.release().await;
        }
        // The sentinel follows the detached writer on the sole blocking thread.
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        assert_eq!(
            std::fs::read_dir(parent).unwrap().count(),
            1,
            "cancelled atomic write left a temporary private resource"
        );
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"complete old resource"
        );
    });
}

#[test]
fn cancel_while_the_public_store_writer_is_queued_cleans_its_temporary_file() {
    cancel_public_store(false);
}

#[test]
fn cancel_after_the_public_store_writer_completes_cleans_its_unclaimed_result() {
    cancel_public_store(true);
}
