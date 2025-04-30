# 1. 停止所有可能使用OpenSSL的服务
sudo systemctl stop ssh nginx apache2 2>/dev/null || true

# 2. 卸载OpenSSL相关包
sudo apt-get remove --purge libssl-dev libssl3 openssl -y
sudo apt-get autoremove -y

# 3. 手动删除剩余的OpenSSL文件
# 头文件
sudo rm -rf /usr/include/openssl
sudo rm -rf /usr/local/include/openssl

# 库文件
sudo rm -f /usr/lib/libssl*
sudo rm -f /usr/lib/*/libssl*
sudo rm -f /usr/lib/libcrypto*
sudo rm -f /usr/lib/*/libcrypto*
sudo rm -f /usr/local/lib/libssl*
sudo rm -f /usr/local/lib/libcrypto*

# 二进制文件
sudo rm -f /usr/bin/openssl
sudo rm -f /usr/local/bin/openssl

# 配置文件
sudo rm -rf /usr/local/ssl
sudo rm -rf /etc/ssl
sudo rm -f /etc/ld.so.conf.d/*openssl*.conf

# pkgconfig文件
sudo rm -f /usr/lib/pkgconfig/libssl.pc
sudo rm -f /usr/lib/pkgconfig/libcrypto.pc
sudo rm -f /usr/lib/pkgconfig/openssl.pc
sudo rm -f /usr/lib/*/pkgconfig/libssl.pc
sudo rm -f /usr/lib/*/pkgconfig/libcrypto.pc
sudo rm -f /usr/lib/*/pkgconfig/openssl.pc

# 4. 更新ldconfig缓存
sudo ldconfig

# 5. 检查是否还有OpenSSL文件残留
echo "检查可能的OpenSSL残留文件:"
find /usr -name "*ssl*" | grep -i ssl || echo "未发现明显残留文件"
find /usr -name "*crypto*" | grep -i crypto || echo "未发现明显残留文件"