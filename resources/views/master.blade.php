<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>@yield('title') - Shop Laravel</title>
        <script src="http://cdn.bootcss.com/jquery/1.11.0/jquery.min.js" type="text/javascript"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" rel="stylesheet" type="text/css" />
        <link href=" https://netdna.bootstrapcdn.com/font-awesome/4.5.0/css/font-awesome.min.css " rel="stylesheet" type="text/css" />
        <link href="/css/style.css" rel="stylesheet" type="text/css" />
    </head>
    <boby>
        <header>
            <ul class="nav">
                <li><a href="/">回首頁</a></li>
                @if(session()->has('user_id'))
                    <li><a href="/user/auth/sign-out">登出</a></li>
                @else
                    <li><a href="/user/auth/sign-in">登入</a></li>
                    <li><a href="/user/auth/facebook-sign-in">Facebook登入</a></li>
                    <li><a href="/user/auth/sign-up">註冊</a></li>
                @endif
            </ul>
        </header>
        <div class="container">
            @yield('content')
        </div>
        <footer>
            <a href="#">聯絡我們</a>
        </footer>
    </body>
</html>