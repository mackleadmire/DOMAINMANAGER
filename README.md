# DOMAINMANAGER
/*
 * AUTHOR :LEE
 * 本脚本工具主要用于渗透初期的踩点工作，支持对wvs，issput，nmap sl中搜集到的域名和ip的管理
 * 函数说明:
 * A.common类中collectTxt($dirname)，合并文件夹中所有的TXT到/sr/temp.txt中
 * B.common类中sortUnique($sortfilename) 去重排序某个文件并保存到sort-unique.txt中,如果有temp.txt会最终删除
 * C.getdomain类中getFinalDomain() 主要是分离域名和ip(按行分离),再输出再去重排序到sort-unique.txt中
 * D.compared类中findDomainCompare($a,$b,$c)， 运用的是array_diff这个功能，去除某个文件中和别人的交集，到filter.txt中
 * 比如checkwait中是否在alreadycheck中的相同的域名，把它去掉，也相当于去重，array_diff这个功能自己也写了一个类似的函数
 * E.getRurl类中testUrl($a,$b)方法，通过curl探测目标的响应码200等，采集指纹，输出到headcode.txt中
 * F.wvsScanLog类中public方法scansaves($dirname),其他都是private，是对wvs的扫描结果进行批量检测，看看哪些有高危漏洞，快速而且使用简单
 *
 *  本架构很简单，分三层，第一层函数实现层，也就是ABCDEF，第二层功能实例化层,包含class:
 *  mainClass -m,manageAC -uac,unisortDir -ua-uc,filterAC -fac-of,TestUrl -gf-ot,onlyCollected -oc,onlySortUnied -os,onlyCSU -ocs,onlyGetdomain -og,iniDir -i
 *  最后一层是功能执行层，包括class：choseStart,参数基本控制在这个层面上，方便管理修改
 *
 * 管理过程：
 * 1.初始化创建目录(php urlmanager-commonclass.php -i) initial
 * 目录有alreadychecked（已经检测过的域名或ip）checkwait（等待检测的域名或ip）
 * 目录ACfilter 存放checkwait中和alreadychecked有交集的部分去重，文件是filter.txt
 * 目录final中存放final.txt,是对filter.txt 探测80,443端口是否开启筛选的最终url
 * 目录resbak,中存放 headcode.txt中记录响应值 有cookie ，服务器类型，是不是301跳转等
 *
 * 2（php urlmanager-commonclass.php -m dirname） 包含ABCDE函数
 * 主要针对nmap -sL，域名和ip不分离，而且域名不带http协议，有很多域名也无法用浏览器打开，
 * 所以此功能主要是合并 sL 生成的txt文件，然后分离域名和ip同时去重排序，在域名前填加http://协议，然后CURL探测响应头
 * 比如 200，cookie，Server: Microsoft-IIS/6.0等，返回状态码是0和404的url都筛选掉，输出到checkwait中的newIp.txt中
 * 等待进一步检测，比如把这些可以直接复制的域名扔到wvs批量扫描一下，或者手工检测，节约了大量人力
 *
 * 3.-ua,-uc,-uac功能上相同包含ABC三个函数功能，是对chekwait,alreadchecked文件夹中的TXT文本合并并去重排序分离域名和ip，
 * 比如 http://xx.160.12.105/，http://xx.160.12.105:80/重复了会去除一个
 * a代表alreadchecked，c代表chekwait，ac代表同时,
 *
 * 4.-fac,包含D函数，检查checkwait中的域名是否在alreadychecked中也有common的部分，去掉common的部分在ACfilter中生成 真正新发现的域名
 *
 * 5.-gf 包含E函数，对ACfilter中filter.txt探测其中的curl响应头信息
 *
 * 6.-w dirname 包含F函数，此功能是批量扫描wvs日志，发现高危漏洞的保存到sr文件中，同时扫描完成的输送到alreadychecked中，
 * 扫描流产的输送到checkwait中
 *-----------------------------------------------------------------------------------------------------------
 * 如果，想指定某个文件夹或某个文件使用上面的这些功能，可以用-ox命令
 * ---------------------------------------------------------------------------------------------------------
 * 7.-oc 包含函数A，可以指定文件夹进行合并TXT
 *
 * 8.-os dirname filename，包含函数B，可以指定文件夹中的某个文件去重排序
 *
 * 9 -ocs 函数A和B的合并，合并TXT然后去重排序
 *
 * 10 -ou dirname ，包含ABC三个函数功能，可以指定文件夹进行合并TXT，去重排序分离ip和域名
 *
 * 11 -og dirname filename 包含函数C，指定某文件夹下某个文件分离ip和域名
 *
 * 12 -of dirname filenameA filenameB，包含函数D，指定对某个文件夹下，对文件A去掉和B中相同的部分，输出到./sr/filter.txt中
 *
 * 13 -ot dirname ,filename ，包含函数E,指定对某个文件夹下文件，探测CURl返回响应头结果，输出到final中
 * *如果不需要分离ip和域名，可以直接把搜集到的域名或ip放入checkwait 中的TXT文本中，然后使用-ox功能分别处理
 */
