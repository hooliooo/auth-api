use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to create listener");

    rest_api::run(listener)
        .await
        .expect("Failed to bind address")
}
