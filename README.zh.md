# CertAuto

**Rust 自动 HTTPS/TLS 证书管理库，基于 ACME 协议。**

<!-- badges -->
[![Crates.io](https://img.shields.io/crates/v/certauto.svg)](https://crates.io/crates/certauto)
[![Documentation](https://docs.rs/certauto/badge.svg)](https://docs.rs/certauto)
[![License](https://img.shields.io/crates/l/certauto.svg)](LICENSE)

[English](README.md) | **简体中文** | [繁體中文](README.zh-hant.md)

CertAuto 为 Rust 程序提供生产级的自动证书管理：从任何 ACME 兼容的证书颁发机构（CA）自动获取、续期和服务 TLS 证书，只需几行代码。

```rust
use certauto::Config;

#[tokio::main]
async fn main() -> certauto::Result<()> {
    let domains = vec!["example.com".into()];
    let tls_config = certauto::manage(&domains).await?;
    // 将 tls_config 用于 tokio-rustls、hyper、axum、salvo 等框架
    Ok(())
}
```

---

## 目录

- [功能特性](#功能特性)
- [环境要求](#环境要求)
- [安装](#安装)
- [快速开始](#快速开始)
- [使用示例](#使用示例)
  - [基础用法 -- 使用默认配置管理证书](#基础用法----使用默认配置管理证书)
  - [自定义 CA 和邮箱](#自定义-ca-和邮箱)
  - [DNS-01 验证（通配符证书）](#dns-01-验证通配符证书)
  - [ZeroSSL](#zerossl)
  - [自定义存储后端](#自定义存储后端)
  - [按需 TLS](#按需-tls)
  - [事件回调](#事件回调)
- [架构概览](#架构概览)
- [ACME 验证方式](#acme-验证方式)
  - [HTTP-01 验证](#http-01-验证)
  - [TLS-ALPN-01 验证](#tls-alpn-01-验证)
  - [DNS-01 验证](#dns-01-验证)
- [存储](#存储)
- [证书维护](#证书维护)
- [按需 TLS（详细说明）](#按需-tls详细说明)
- [API 参考](#api-参考)
- [许可证](#许可证)

---

## 功能特性

- **全自动证书管理** -- 无需人工干预即可获取、续期和缓存 TLS 证书
- **支持全部三种 ACME 验证方式** -- HTTP-01、TLS-ALPN-01 和 DNS-01
- **多 CA 支持** -- Let's Encrypt（生产和测试环境）、ZeroSSL、Google Trust Services，或任何 ACME 兼容的 CA
- **OCSP 装订** -- 自动获取并装订 OCSP 响应，提升隐私和性能；装订结果持久化到存储中，重启后仍然可用
- **通配符证书** -- 通过 DNS-01 验证配合可插拔的 `DnsProvider` trait 实现
- **按需 TLS** -- 在 TLS 握手时为未预配置的域名获取证书，支持白名单、决策函数和速率限制
- **证书缓存** -- 内存中的 `CertCache`，基于域名索引和通配符匹配，实现快速 TLS 握手查找
- **可配置密钥类型** -- ECDSA P-256（默认）、ECDSA P-384、RSA 2048、RSA 4096 和 Ed25519
- **后台维护** -- 自动续期检查（每 10 分钟）和 OCSP 装订刷新（每 1 小时）
- **内置速率限制** -- 防止向 CA 发送过多请求
- **指数退避重试** -- 失败的证书操作会以递增的延迟进行重试（最长 30 天）
- **分布式验证求解** -- `DistributedSolver` 通过共享 `Storage` 在多实例间协调验证，支持负载均衡器后的集群部署
- **文件系统存储与原子写入** -- 默认的 `FileStorage` 使用先写临时文件再重命名的方式确保崩溃安全；分布式锁文件通过后台保活任务实现集群协调
- **自定义存储后端** -- 实现 `Storage` trait 即可使用数据库、KV 存储或任何其他持久化层
- **事件回调** -- 监听证书生命周期事件（`cert_obtaining`、`cert_obtained`、`cert_renewed`、`cert_failed`、`cert_revoked` 等）
- **Builder 模式** -- 人性化的 `Config::builder()`、`AcmeIssuer::builder()` 和 `ZeroSslIssuer::builder()` 简化配置
- **外部账户绑定（EAB）** -- 一等支持需要 EAB 的 CA（如 ZeroSSL）
- **证书链偏好** -- 按根证书/颁发者 Common Name 或链大小选择首选证书链
- **证书吊销** -- 通过 ACME 协议吊销受损的证书
- **原生 rustls 集成** -- `CertResolver` 实现了 `rustls::server::ResolvesServerCert`，可直接接入任何基于 rustls 的服务器

## 环境要求

1. **Rust 2021 edition** 和 Tokio 异步运行时
2. 您控制的**公共 DNS 域名**，A/AAAA 记录指向您的服务器
3. **80 端口**可从公网访问（用于 HTTP-01 验证），和/或 **443 端口**（用于 TLS-ALPN-01 验证）
   - 可以通过端口转发实现
   - 或使用 DNS-01 验证完全免除端口要求
   - 这是 ACME 协议的要求，并非本库的限制
4. **持久化存储**用于证书、密钥和元数据
   - 默认：本地文件系统（Linux: `~/.local/share/certauto`，macOS: `~/Library/Application Support/certauto`，Windows: `%APPDATA%/certauto`）
   - 可通过 `Storage` trait 使用自定义后端

> **使用本库之前，您的域名必须将 A/AAAA 记录指向您的服务器（除非使用 DNS-01 验证）。**

## 安装

在 `Cargo.toml` 中添加 `certauto`：

```toml
[dependencies]
certauto = "0.1"
tokio = { version = "1", features = ["full"] }
```

## 快速开始

最简单的使用方式 -- 一个函数调用管理一切：

```rust
use certauto::Config;

#[tokio::main]
async fn main() -> certauto::Result<()> {
    let domains = vec!["example.com".into()];

    // 获取（或从存储加载）证书，返回可直接使用的
    // rustls::ServerConfig，用于任何 TLS 服务器。
    let tls_config = certauto::manage(&domains).await?;

    // 将 tls_config 用于 tokio-rustls、hyper、axum、salvo 等框架
    Ok(())
}
```

执行以上代码将会：
1. 在操作系统默认目录创建 `FileStorage`。
2. 从 Let's Encrypt（生产环境）为指定域名获取证书。
3. 返回配置了 `CertResolver` 的 `rustls::ServerConfig`，可服务托管的证书。

## 使用示例

### 基础用法 -- 使用默认配置管理证书

```rust
use std::sync::Arc;
use certauto::{Config, FileStorage, Storage};

#[tokio::main]
async fn main() -> certauto::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());
    let config = Config::builder()
        .storage(storage)
        .build();

    let domains = vec!["example.com".into(), "www.example.com".into()];
    config.manage_sync(&domains).await?;

    // 启动后台维护（续期 + OCSP 刷新）
    let _handle = certauto::start_maintenance(&config);

    Ok(())
}
```

### 自定义 CA 和邮箱

```rust
use std::sync::Arc;
use certauto::{
    AcmeIssuer, Config, FileStorage, Storage,
    LETS_ENCRYPT_STAGING,
};

let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());

let issuer = AcmeIssuer::builder()
    .ca(LETS_ENCRYPT_STAGING) // 开发阶段使用测试环境！
    .email("admin@example.com")
    .agreed(true)
    .storage(storage.clone())
    .build();

let config = Config::builder()
    .storage(storage)
    .issuers(vec![Arc::new(issuer)])
    .build();
```

### DNS-01 验证（通配符证书）

DNS-01 验证是获取通配符证书的唯一方式，即使服务器不可公网访问也能正常工作。

```rust
use std::sync::Arc;
use certauto::{AcmeIssuer, Dns01Solver, DnsProvider};

// 为您的 DNS 服务（Cloudflare、Route53 等）实现 DnsProvider
let dns_solver = Arc::new(Dns01Solver::new(
    Box::new(my_dns_provider),
));

let issuer = AcmeIssuer::builder()
    .dns01_solver(dns_solver)
    .email("admin@example.com")
    .agreed(true)
    .storage(storage.clone())
    .build();

// 现在可以获取通配符证书：
let domains = vec!["*.example.com".into()];
```

实现 DNS 提供者需要实现 `DnsProvider` trait：

```rust
use async_trait::async_trait;
use certauto::{DnsProvider, Result};

struct MyDnsProvider { /* ... */ }

#[async_trait]
impl DnsProvider for MyDnsProvider {
    async fn set_record(
        &self, zone: &str, name: &str, value: &str, ttl: u32,
    ) -> Result<()> {
        // 通过 DNS 提供者的 API 创建 TXT 记录
        Ok(())
    }

    async fn delete_record(
        &self, zone: &str, name: &str, value: &str,
    ) -> Result<()> {
        // 删除 TXT 记录
        Ok(())
    }
}
```

### ZeroSSL

ZeroSSL 通过 ACME 协议提供免费证书，需要外部账户绑定（EAB）。CertAuto 使用您的 ZeroSSL API 密钥自动处理 EAB 配置。

```rust
use std::sync::Arc;
use certauto::{Config, FileStorage, Storage, ZeroSslIssuer};

let storage: Arc<dyn Storage> = Arc::new(FileStorage::default());

let issuer = ZeroSslIssuer::builder()
    .api_key("your-zerossl-api-key")
    .email("admin@example.com")
    .storage(storage.clone())
    .build()
    .await?;

let config = Config::builder()
    .storage(storage)
    .issuers(vec![Arc::new(issuer)])
    .build();
```

### 自定义存储后端

实现 `Storage` trait 即可使用数据库、Redis、S3 或任何其他持久化层。所有共享同一存储的实例被视为同一集群的成员。

```rust
use async_trait::async_trait;
use certauto::storage::{Storage, KeyInfo};
use certauto::Result;

struct MyDatabaseStorage { /* ... */ }

#[async_trait]
impl Storage for MyDatabaseStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        // 写入数据库
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        // 从数据库读取
        todo!()
    }

    async fn delete(&self, key: &str) -> Result<()> {
        // 从数据库删除
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        // 检查键是否存在
        todo!()
    }

    async fn list(&self, path: &str, recursive: bool) -> Result<Vec<String>> {
        // 列出指定前缀下的键
        todo!()
    }

    async fn stat(&self, key: &str) -> Result<KeyInfo> {
        // 返回键的元数据
        todo!()
    }

    async fn lock(&self, name: &str) -> Result<()> {
        // 获取分布式锁
        Ok(())
    }

    async fn unlock(&self, name: &str) -> Result<()> {
        // 释放分布式锁
        Ok(())
    }
}
```

### 按需 TLS

按需 TLS 在 TLS 握手时为未预配置的域名获取证书。务必通过白名单或决策函数进行限制，以防止滥用。

```rust
use std::collections::HashSet;
use std::sync::Arc;
use certauto::OnDemandConfig;

let on_demand = Arc::new(OnDemandConfig {
    host_allowlist: Some(HashSet::from([
        "a.example.com".into(),
        "b.example.com".into(),
    ])),
    decision_func: None,
    rate_limit: None,
    obtain_func: None, // 由 Config 内部自动连接
});

let config = Config::builder()
    .storage(storage)
    .on_demand(on_demand)
    .build();
```

### 事件回调

订阅证书生命周期事件，用于日志记录、监控或告警：

```rust
use std::sync::Arc;

let config = Config::builder()
    .storage(storage)
    .on_event(Arc::new(|event: &str, data: &serde_json::Value| {
        println!("证书事件: {} {:?}", event, data);
    }))
    .build();
```

支持的事件包括：
- `cert_obtaining` -- 正在开始获取证书
- `cert_obtained` -- 证书获取成功
- `cert_renewed` -- 证书续期成功
- `cert_failed` -- 证书获取或续期失败
- `cert_revoked` -- 证书已被吊销
- `cached_managed_cert` -- 托管证书已从存储加载到缓存

## 架构概览

```
                    +-----------+
                    |  Config   |  中心协调器
                    +-----+-----+
                          |
          +---------------+---------------+
          |               |               |
    +-----v-----+   +----v----+   +------v------+
    |  Issuer   |   |  Cache  |   |   Storage   |
    +-----------+   +---------+   +-------------+
          |               |               |
    +-----v-----+   +----v--------+  +---v-----------+
    | AcmeIssuer|   | CertResolver|  | FileStorage   |
    | ZeroSSL   |   | (rustls)    |  | (或自定义)     |
    +-----------+   +-------------+  +---------------+
          |
    +-----v-------+
    |  AcmeClient  |----> ACME CA（Let's Encrypt、ZeroSSL 等）
    +--------------+

    +------------------+
    | start_maintenance| ---> 续期循环（每 10 分钟）
    |                  | ---> OCSP 刷新循环（每 1 小时）
    +------------------+
```

**核心组件：**

| 组件 | 职责 |
|---|---|
| `Config` | 中心入口；协调获取、续期、吊销和缓存操作 |
| `AcmeIssuer` / `ZeroSslIssuer` | 实现 `Issuer` trait；驱动 ACME 协议流程 |
| `AcmeClient` | 底层 ACME HTTP 客户端（目录、nonce、JWS 签名、订单管理） |
| `CertCache` | 内存证书存储，按域名索引（支持通配符匹配） |
| `CertResolver` | 实现 `rustls::server::ResolvesServerCert`；在 TLS 握手时解析证书 |
| `Storage` / `FileStorage` | 持久化键值存储，支持分布式锁 |
| `start_maintenance` | 后台 tokio 任务，用于自动续期和 OCSP 刷新 |

## ACME 验证方式

ACME 协议通过验证（challenge）来验证域名所有权。CertAuto 支持全部三种标准验证类型。

### HTTP-01 验证

HTTP-01 验证通过在 `http://<domain>/.well-known/acme-challenge/<token>`（**80 端口**）提供特定令牌来证明域名控制权。

CertAuto 的 `Http01Solver` 启动一个轻量 HTTP 服务器，自动提供验证响应。服务器在验证开始时启动，完成后停止。

```rust
use certauto::Http01Solver;

let solver = Http01Solver::new(80); // 或 Http01Solver::default()
```

**要求：** 80 端口必须可从公网访问（直接或通过端口转发）。

### TLS-ALPN-01 验证

TLS-ALPN-01 验证通过在 **443 端口**的 TLS 握手中展示包含特殊 `acmeIdentifier` 扩展的自签名证书来证明域名控制权，通过 `acme-tls/1` ALPN 协议协商。

CertAuto 的 `TlsAlpn01Solver` 生成临时验证证书并在临时 TLS 监听器上提供服务。

```rust
use certauto::TlsAlpn01Solver;

let solver = TlsAlpn01Solver::new(443); // 或 TlsAlpn01Solver::default()
```

**要求：** 443 端口必须可从公网访问。这通常是最方便的验证类型，因为它使用与生产 TLS 服务器相同的端口。

### DNS-01 验证

DNS-01 验证通过在 `_acme-challenge.<domain>` 创建特定的 TXT 记录来证明域名控制权。这是**唯一**支持通配符证书的验证类型，且不要求服务器可从公网访问。

CertAuto 的 `Dns01Solver` 接受一个 `DnsProvider` 实现，通过 DNS 提供者的 API 创建和删除 TXT 记录。它会自动等待 DNS 传播完成后再通知 CA。

```rust
use certauto::Dns01Solver;

let solver = Dns01Solver::new(Box::new(my_cloudflare_provider));
// 使用自定义传播设置：
let solver = Dns01Solver::with_timeouts(
    Box::new(my_provider),
    std::time::Duration::from_secs(180),  // 传播超时
    std::time::Duration::from_secs(5),    // 检查间隔
);
```

**要求：** 提供 API 的 DNS 提供者，以及 `DnsProvider` trait 的实现。

## 存储

CertAuto 需要持久化存储来保存证书、私钥、元数据、OCSP 装订和锁文件。存储通过 `Storage` trait 抽象，可以轻松切换后端。

**默认：`FileStorage`**

内置的 `FileStorage` 将所有数据存储在本地文件系统上，具有以下特性：

- **原子写入** -- 数据先写入临时文件，再原子重命名到目标位置，防止部分读取
- **分布式锁** -- 锁文件包含 JSON 时间戳，由后台保活任务每 5 秒刷新；超过 10 秒的过期锁会被自动清除
- **平台感知路径** -- 默认使用 `~/.local/share/certauto`（Linux）、`~/Library/Application Support/certauto`（macOS）或 `%APPDATA%/certauto`（Windows）

**集群：** 共享同一存储后端的实例被视为同一集群。对于 `FileStorage`，挂载共享网络文件夹即可。对于自定义后端，确保所有实例指向同一数据库/服务。

**存储目录结构：**

```
<root>/
  certificates/<issuer>/<domain>/
    <domain>.crt    -- PEM 证书链
    <domain>.key    -- PEM 私钥
    <domain>.json   -- 元数据（SANs、颁发者信息）
  ocsp/
    <domain>-<hash> -- 缓存的 OCSP 响应
  acme/<issuer>/
    users/<email>/  -- ACME 账户数据
  locks/
    <name>.lock     -- 分布式锁文件
```

## 证书维护

CertAuto 通过 `certauto::start_maintenance()` 运行后台维护，它会生成一个 tokio 任务执行两个定期循环：

1. **续期循环**（默认每 10 分钟） -- 遍历缓存中所有托管证书，续期进入续期窗口的证书（默认在证书有效期剩余不足 1/3 时触发续期）

2. **OCSP 刷新循环**（默认每 1 小时） -- 为所有缓存的证书获取最新的 OCSP 响应并持久化到存储

两个循环都遵循 `CertCache::stop()` 信号以实现优雅关闭。

```rust
let config = Config::builder().storage(storage).build();

// 启动后台维护
let handle = certauto::start_maintenance(&config);

// ... 稍后优雅停止：
// config.cache.stop().await;
// handle.await;
```

## 按需 TLS（详细说明）

按需 TLS 在 TLS 握手时为未预配置的域名获取证书。当收到包含未知 SNI 值的 `ClientHello` 时，`CertResolver` 可以触发后台证书获取，使同一域名的后续握手成功。

这个功能强大但必须谨慎限制以防止滥用：

| 限制方式 | 说明 |
|---|---|
| `host_allowlist` | 允许的主机名 `HashSet<String>`（不区分大小写） |
| `decision_func` | 动态允许/拒绝逻辑的闭包 `Fn(&str) -> bool` |
| `rate_limit` | 可选的 `RateLimiter` 限制颁发速率 |

如果 `decision_func` 和 `host_allowlist` 均未配置，按需颁发将被**拒绝**（默认安全），以防止无限制的证书请求。

由于 `rustls::server::ResolvesServerCert::resolve` 是同步方法，按需获取会在后台生成任务。当前握手会收到默认证书（或 `None`）；同一域名的下次握手将在缓存中找到证书。

## API 参考

完整的 API 文档可在 [docs.rs](https://docs.rs/certauto) 查看。

关键入口点：

- [`certauto::manage()`](https://docs.rs/certauto/latest/certauto/fn.manage.html) -- 最高层函数，返回可直接使用的 `rustls::ServerConfig`
- [`Config::builder()`](https://docs.rs/certauto/latest/certauto/struct.ConfigBuilder.html) -- 配置并构建 `Config`
- [`AcmeIssuer::builder()`](https://docs.rs/certauto/latest/certauto/struct.AcmeIssuerBuilder.html) -- 配置 ACME 颁发者
- [`Storage` trait](https://docs.rs/certauto/latest/certauto/trait.Storage.html) -- 实现自定义存储后端
- [`Solver` trait](https://docs.rs/certauto/latest/certauto/trait.Solver.html) -- 实现自定义验证求解器
- [`DnsProvider` trait](https://docs.rs/certauto/latest/certauto/trait.DnsProvider.html) -- 实现 DNS 提供者（用于 DNS-01 验证）

## 开发和测试

Let's Encrypt 对其生产端点施加[严格的速率限制](https://letsencrypt.org/docs/rate-limits/)。开发阶段请始终使用**测试**端点：

```rust
use certauto::LETS_ENCRYPT_STAGING;

let issuer = AcmeIssuer::builder()
    .ca(LETS_ENCRYPT_STAGING)
    .email("dev@example.com")
    .agreed(true)
    .storage(storage.clone())
    .build();
```

测试证书不受公共信任，但速率限制宽松得多。

## 许可证

CertAuto 采用 [MIT 许可证](LICENSE-MIT) 和 [Apache 许可证 2.0](LICENSE-APACHE) 双重许可。您可以选择其中任何一个。
