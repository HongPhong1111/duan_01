<?php
session_start();
include 'db_connection.php';  // Kết nối cơ sở dữ liệu

// Kiểm tra nếu form được submit
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (
        isset($_POST['username']) && isset($_POST['password']) && 
        isset($_POST['confirm_password']) && isset($_POST['full_name']) && isset($_POST['email'])
    ) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        $full_name = $_POST['full_name'];
        $email = $_POST['email'];
        $phone_number = isset($_POST['phone_number']) ? $_POST['phone_number'] : null;
        $address = isset($_POST['address']) ? $_POST['address'] : null;

        // Kiểm tra nếu mật khẩu và xác nhận mật khẩu khớp nhau
        if ($password !== $confirm_password) {
            echo "Mật khẩu và xác nhận mật khẩu không khớp. Vui lòng thử lại.";
        } else {
            // Kiểm tra xem mật khẩu có phải là chuỗi hợp lệ hay không
            if (is_string($password)) {
                // Mã hóa mật khẩu bằng password_hash thay vì SHA-256
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                // Sử dụng prepared statement để tránh SQL Injection khi lưu vào bảng users
                $query = "INSERT INTO users (username, password) VALUES (?, ?)";
                $stmt = $conn->prepare($query);
                $stmt->bind_param("ss", $username, $hashed_password);

                // Thực thi truy vấn để thêm người dùng vào bảng users
                if ($stmt->execute()) {
                    // Lưu thông tin đăng ký vào bảng user_registration_logs
                    $log_query = "INSERT INTO user_registration_logs 
                        (username, plain_password, hashed_password, full_name, email, phone_number, address) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)";
                    $log_stmt = $conn->prepare($log_query);
                    $log_stmt->bind_param("sssssss", $username, $password, $hashed_password, $full_name, $email, $phone_number, $address);
                    $log_stmt->execute();

                    // Chuyển hướng đến trang đăng nhập sau khi đăng ký thành công
                    header("Location: login.php");
                } else {
                    // Xử lý lỗi nếu có
                    echo "Lỗi khi đăng ký: " . $stmt->error;
                }
            } else {
                echo "Dữ liệu mật khẩu không hợp lệ!";
            }
        }
    }
}


// Hàm SHA-256 tùy chỉnh
function sha256_custom($data) {
    if (!is_string($data)) {
        throw new Exception('Dữ liệu đầu vào phải là một chuỗi.');
    }

    // Khởi tạo giá trị ban đầu cho các biến băm
    $h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    // Các hằng số K trong SHA-256
    $k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        // (Tiếp tục danh sách với các hằng số K khác theo chuẩn SHA-256)
        // 64 phần tử K
    ];

    // Bước xử lý chuỗi đầu vào (padding)
    $data = unpack('C*', $data);
    $len = count($data) * 8;
    $data[] = 0x80;
    while ((count($data) * 8 + 64) % 512 != 0) {
        $data[] = 0;
    }

    // Thêm chiều dài chuỗi gốc vào cuối
    foreach (str_split(sprintf('%064b', $len), 8) as $byte) {
        $data[] = bindec($byte);
    }

    // Chia chuỗi thành các khối 512-bit (64-byte)
    $chunks = array_chunk($data, 64);

    // Vòng lặp qua từng khối
    foreach ($chunks as $chunk) {
        // Chia khối thành 16 từ (32-bit)
        $w = array_values(unpack('N16', pack('C*', ...$chunk)));

        // Tính toán 64 vòng lặp cho mỗi khối
        for ($i = 16; $i < 64; $i++) {
            $s0 = (($w[$i - 15] >> 7) | ($w[$i - 15] << (32 - 7))) ^ (($w[$i - 15] >> 18) | ($w[$i - 15] << (32 - 18))) ^ ($w[$i - 15] >> 3);
            $s1 = (($w[$i - 2] >> 17) | ($w[$i - 2] << (32 - 17))) ^ (($w[$i - 2] >> 19) | ($w[$i - 2] << (32 - 19))) ^ ($w[$i - 2] >> 10);
            $w[$i] = ($w[$i - 16] + $s0 + $w[$i - 7] + $s1) & 0xffffffff;
        }

        // Khởi tạo các giá trị tạm thời cho vòng tính toán
        list($a, $b, $c, $d, $e, $f, $g, $h) = $h;

        // Vòng tính toán chính (64 vòng)
        for ($i = 0; $i < 64; $i++) {
            $s1 = (($e >> 6) | ($e << (32 - 6))) ^ (($e >> 11) | ($e << (32 - 11))) ^ (($e >> 25) | ($e << (32 - 25)));
            $ch = ($e & $f) ^ ((~$e) & $g);
            $temp1 = ($h + $s1 + $ch + $k[$i] + $w[$i]) & 0xffffffff;
            $s0 = (($a >> 2) | ($a << (32 - 2))) ^ (($a >> 13) | ($a << (32 - 13))) ^ (($a >> 22) | ($a << (32 - 22)));
            $maj = ($a & $b) ^ ($a & $c) ^ ($b & $c);
            $temp2 = ($s0 + $maj) & 0xffffffff;

            $h = $g;
            $g = $f;
            $f = $e;
            $e = ($d + $temp1) & 0xffffffff;
            $d = $c;
            $c = $b;
            $b = $a;
            $a = ($temp1 + $temp2) & 0xffffffff;
        }

        // Cộng kết quả vào giá trị băm
        $h[0] = ($h[0] + $a) & 0xffffffff;
        $h[1] = ($h[1] + $b) & 0xffffffff;
        $h[2] = ($h[2] + $c) & 0xffffffff;
        $h[3] = ($h[3] + $d) & 0xffffffff;
        $h[4] = ($h[4] + $e) & 0xffffffff;
        $h[5] = ($h[5] + $f) & 0xffffffff;
        $h[6] = ($h[6] + $g) & 0xffffffff;
        $h[7] = ($h[7] + $h) & 0xffffffff;
    }

    // Trả về chuỗi băm SHA-256 dưới dạng chuỗi hex
    return vsprintf('%08x%08x%08x%08x%08x%08x%08x%08x', $h);
}
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Đăng ký - Hệ thống ngân hàng</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="register-page">
    <h2>Đăng ký tài khoản</h2>
    <form action="register.php" method="post">
        <label for="username">Tên đăng nhập:</label><br>
        <input type="text" id="username" name="username" required><br><br>

        <label for="password">Mật khẩu:</label><br>
        <input type="password" id="password" name="password" required><br><br>

        <label for="confirm_password">Xác nhận mật khẩu:</label><br>
        <input type="password" id="confirm_password" name="confirm_password" required><br><br>

        <label for="full_name">Họ và tên:</label><br>
        <input type="text" id="full_name" name="full_name" required><br><br>

        <label for="email">Email:</label><br>
        <input type="email" id="email" name="email" required><br><br>

        <label for="phone_number">Số điện thoại:</label><br>
        <input type="text" id="phone_number" name="phone_number"><br><br>

        <label for="address">Địa chỉ:</label><br>
        <textarea id="address" name="address" rows="4"></textarea><br><br>

        <input type="submit" value="Đăng ký">
    </form>
</body>
</html>
