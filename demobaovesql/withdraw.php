<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rút tiền - Hệ thống ngân hàng</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="withdraw">
    <div class="container">
        <h2>Rút tiền từ tài khoản của bạn</h2>
        <form action="withdraw_handler.php" method="post">
            <label for="amount">Số tiền cần rút:</label>
            <input type="number" id="amount" name="amount" step="0.01" required>
            <input type="submit" value="Rút tiền">
        </form>
    </div>
</body>
</html>
