use core::str;
use smoltcp::phy::{self, Medium};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;

fn main() {
    // 创建一个模拟的网络设备
    let medium = Medium::Ethernet;
    let mut device = phy::Loopback::new(medium);

    // // 设置网络参数
    // let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 0, 1), 24)];
    let mut config = Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
    config.random_seed = rand::random();

    // 创建网络接口
    let mut iface = Interface::new(config, &mut device, Instant::now());

    // 创建 TCP socket 缓冲区
    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 1500]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 1500]);

    // 创建 TCP socket
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    // 创建 socket 集合并添加 TCP socket
    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    // 连接到服务器（这里假设我们要连接到本地的 8000 端口）
    let remote_endpoint = (IpAddress::v4(127, 0, 0, 1), 8000);
    {
        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        match socket.connect(iface.context(), remote_endpoint, 49500) {
            Ok(()) => println!("Connection initiated successfully"),
            Err(e) => {
                eprintln!("Failed to initiate connection: {:?}", e);
                return;
            }
        }
    }

    let mut tcp_active = false;
    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if socket.is_active() && !tcp_active {
            println!("Connected");
        } else if !socket.is_active() && tcp_active {
            println!("Disconnected");
            break;
        }
        tcp_active = socket.is_active();

        if socket.may_recv() {
            let data = socket
                .recv(|data| {
                    let mut data = data.to_owned();
                    if !data.is_empty() {
                        println!(
                            "Received data: {:?}",
                            str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
                        );
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    (data.len(), data)
                })
                .unwrap();
            if socket.can_send() && !data.is_empty() {
                println!(
                    "Sending data: {:?}",
                    str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
                );
                socket.send_slice(&data[..]).unwrap();
            }
        } else if socket.may_send() {
            println!("Closing connection");
            socket.close();
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    println!("TCP test completed successfully");
}