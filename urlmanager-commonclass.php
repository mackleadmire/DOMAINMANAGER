<?php
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
 * 比如 http://141.160.12.105/，http://141.160.12.105:80/重复了会去除一个
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

//echo "------------------------Miss Input,Underline Is Help Info-----------------------------\r\n";
//echo "---------------------------------------------------------------------------------------\r\n";
//echo "php urlmanager-commonclass.php -i\r\n";
//echo "-i initial,create ini_dir and ini_file\r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -m dirname\r\n";
//echo "-m include whole process for manage url,function A,B,C,D,E\r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -ua\r\n";
//echo "-ua Combine TXT,unique,sort and seperate domain and ip in alreadychecked,function A,B,C \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -uc\r\n";
//echo "-uc Combine TXT,unique,sort and seperate domain and ip in checkwait,function A,B,C \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -uac\r\n";
//echo "-uac Combine TXT,unique,sort and seperate domain and ip in alreadychecked and checkwait,function A,B,C \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -fac\r\n";
//echo "-fac checkwait minus which have common in alreadychecked,function D\r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -gf\r\n";
//echo "-gf get headcode response from ACfilter and output data url to final,function E\r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -w dirname\r\n";
//echo "-w wvscanlog which can find highrisk and abort items,function F\r\n";
//echo "--------------------------------------------------------------------------------------------------------\r\n";
//echo "--------If you want use each particular function in different dir,use underline command--------------\r\n";
//echo "--------------------------------------------------------------------------------------------------------\r\n";
//echo "------dirname also can be(./dir/dir/),filename(./dir/dir/file)----------------\r\n";
//echo "php urlmanager-commonclass.php -oc dirname \r\n";
//echo "-oc Combine TXT in dirname,function A \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -os dirname filename \r\n";
//echo "-os dirname filename,unique and sort in dirname,function B \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -ocs dirname \r\n";
//echo "-ocs Combine TXT,unique,sort in dirname,function A,B \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -ou dirname \r\n";
//echo "-ou Combine TXT,unique,sort and seperate domain and ip in dirname,function A,B,C \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -og dirname filename \r\n";
//echo "-og dirname filename, Combine TXT,seperate domain and ip in dirname,function C \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -of dirname filenameA filenameB \r\n";
//echo "-of,dirname which have file A and B, fileA minus which have common in FileB,function D \r\n";
//echo "----------------------\r\n";
//echo "php urlmanager-commonclass.php -ot dirname filename \r\n";
//echo "-ot dirname filename,get curl response headcode with file in dir,function E \r\n";
class common {



    public function mkDir($mkdirname)
    {
        //如果创建的目录不存在，新建这个目录
        if (is_dir($mkdirname) == 0)
            mkdir($mkdirname);
        //如果这个目录存在，删除这个目录，再重新创建
        if (is_dir($mkdirname) == 1)
        {
            $this->deleDir("$mkdirname");
            mkdir($mkdirname);
        }

    }

    public function deleDir($dirnamedel)
    {

        //此删除目录功能只限于目录里是txt文件，其他文件的话，目录删除不掉
        chdir($dirnamedel);

        $arr = scandir("./");

        foreach ($arr as $v)
        {
            if (preg_match("/\.txt/",$v))
            {

                unlink($v);

            }
            else
            {

                continue;  //有其他比如.或者..或者其他不是txt文件的，都跳过继续循环
            }
        }
        chdir("../");
        rmdir($dirnamedel);
    }

    //进入某个文件夹中，并创建sr文件夹，合并文件夹中所有的TXT到/sr/temp.txt中
    public function collectTxt()

    {

        /*
         * 进入dir文件夹，创建 sr文件夹，将所有以.txt文本都写入
         * 保存到./sr/temp.txt文件中
         * global $argv;  //在类里$argv必须命名为全局变量
         * $dirname= $argv[1];
         */


        $arr = scandir("./");
        foreach ($arr as $v)
        {
            if (preg_match("/\.txt/",$v))
            {
                $cont = file_get_contents($v);  //file_get_contents返回的是字符串
                $handle = fopen("./sr/temp.txt","a");   //将文件夹下的.txt的文件都合并到temp.txt中
                fwrite($handle,$cont."\r\n");
                fclose($handle);

            }
            else
            {

                continue;  //有其他比如.或者..或者其他不是txt文件的，都跳过继续循环
            }
        }



    }

   /*
    *  去重排序需要放到数组里，去重排序后，再写入sort-unique.txt中，如果有合并的temp.txt,最后会删除
    */
    public function sortUnique($sortfilename)
    {

        $newlistarr = file($sortfilename);    //去重排序需要用到数组函数，所以用file返回数组
        //先排序后去重
        sort($newlistarr);
        $uniqarr = array_unique($newlistarr);   //去重，再将数组循环遍历保存生成新的去重排序文本到./sr/sort-unique.txt中
        $v2 =join("",$uniqarr);
            //去重复排序生成的文件
            $handlesort = fopen("./sr/sort-unique.txt", "a");
            fwrite($handlesort, $v2);
            fclose($handlesort);
        if(is_file("./sr/temp.txt"))
            unlink("./sr/temp.txt");//将临时文件删除

    }


}


/*
 *getdomain类中getFinalDomain() 主要是分离域名和ip再输出再去重排序到sort-unique.txt中
 */
class getdomain extends common
{
    public function getFinalDomain($filename)
    {
        //  header('Content-type: text/html; charset=utf-8');

//将temp.txt去重排序，并生成sort-unique.txt,然后将temp.txt删除
        $this->sortUnique($filename);
        $a = "./sr/sort-unique.txt";
        $hand = fopen($a,"r");
        $handled = fopen("./sr/domain.txt", "a");


        while(!feof($hand))

        {
            //fgets函数从文本中一行一行读取，但是每行结尾会有换行符，所以用trim去掉，trim去掉前后特殊符号和空字符
            $ip =  trim(fgets($hand));
//用perl正则匹配，preg_match_all对所有的内容进行匹配，并放到二维数组中,ipf匹配ip，df匹配域名
            $ipf = preg_match_all("/[\d]+\.[\d]+\.[\d]+\.[\d]+$/",$ip,$matchesip);  //匹配成功，返回true,测试 echo $matchesip[0][0] . "</br>" . "\r\n";

            $ipfs = preg_match_all("/[\d]+\.[\d]+\.[\d]+\.[\d]+:443/",$ip,$matchesips);

            $ipfh =  preg_match_all("/([\d]+\.[\d]+\.[\d]+\.[\d])+:80/",$ip,$matchesiph);

            $ipe = preg_match_all("/[\d]+\.[\d]+\.[\d]+\.[\d]+/",$ip,$matchesipe);

            $df = preg_match_all("/[\w-]+\.[\w-]+\.[\w-]+\.com|[\w-]+\.[\w-]+\.com|[\w-]+\.com/",$ip,$matchesd); //匹配成功，返回true



//            if($ipfs ==1 || $ipfh ==1)
//            {
//                if($ipfs == 1)
//                {
//
//                    fwrite($handled,"https://" . $matchesips[0][0] . "\r\n");
//
//                }
//                if($ipfh == 1)
//                {
//
//                    fwrite($handled,"http://" . $matchesiph[1][0] . "\r\n");
//
//                }
//            }
//
//            else if($ipf == 1 || $ipe == 1)
//            {
//                if($ipf == 1)
//                {
//
//                    fwrite($handled,"http://" . $matchesips[0][0] . "\r\n");
//
//                }
//                if($ipe == 1)
//                {
//
//                    fwrite($handled,"http://" . $matchesiph[1][0] . "\r\n");
//
//                }
//            }

//保存域名
            if ($df == 1)
            {

                fwrite($handled,"http://" . $matchesd[0][0] . "\r\n");

            }
//保存ip
            if ( $ipf ==1 || $ipfs ==1 || $ipfh ==1|| $ipe==1)
            {
//                if ($ipf == 1)
//                {
//
//
//                    $handleip = fopen("./sr/ip.txt", "a");
//                    fwrite($handleip, "http://" . $matchesip[0][0] . "\r\n");
//                    fclose($handleip);
//
//                }
                if($ipfs == 1)
                {

                    fwrite($handled,"https://" . $matchesips[0][0] . "\r\n");

                }
                if($ipfh == 1)
                {

                    fwrite($handled,"http://" . $matchesiph[1][0] . "\r\n");

                }
                if($ipe == 1)
                {


                    fwrite($handled,"http://" . $matchesipe[0][0] . "\r\n");

                }
            }

//如果域名和ip同时存在，都保存
            if ($ipf ==1 && $df ==1)
            {
                if(is_dir("sr"))
                {
                    $handlea = fopen("./sr/all.txt", "a");
                    fwrite($handlea, "http://" . $matchesd[0][0] . "-------" . $matchesip[0][0] . "\r\n");
                    fclose($handlea);
                }

            }
        }
        fclose($hand);
        fclose($handled);


        if(is_file("./sr/sort-unique.txt"))
            unlink("./sr/sort-unique.txt");//将临时sort-unique文件删除

        $this->sortUnique("./sr/domain.txt");

        if(is_file("./sr/domain.txt"))
            unlink("./sr/domain.txt");//将临时domain文件删除


    }
}


class compared
{

    /*
     * 此脚本用于删除之前已经检查过的域名,同时可以用来消除A中和B相交的部分，不相交的部分输出到C中
     * 没去查函数之前，直接写了个去交集的函数
     */
    public function findDomainCompare($a,$b,$c)
    {
        // header('Content-type: text/html; charset=utf-8');

         //a 文件A，b文件B，c输出到c中
        $filea =file($a);
        $fileb =file($b);
        $filec =array_diff($filea,$fileb);
        $sc = join("",$filec);
        $handp = fopen($c,"a");
        fwrite($handp,$sc);
        fclose($handp);

//下面这个就是没查数组函数之前，自己写的去交集的函数
//去交集思路， A中取出一个值跟B中所有的比较，如果有相同的，把A中这个值替换未空，空值不写入C中，如果不为空，就写入
//后来才查到有个array_diff就是这个功能，也不算白写，练练手了
// header('Content-type: text/html; charset=utf-8');
////打开新域名文档，然后循环读取
//        $handnew = fopen($a,"r");
//        $handp = fopen($c,"a");
//        while(!feof($handnew))
//        {
////用fgets对txt文档一行行读取
//            $ipnew = trim(fgets($handnew));
////打开旧的文档
//            $hand = fopen($b,"r");
//            while (!feof($hand))
//            {
//                $ip = trim(fgets($hand));
////把新的域名放到旧的文档中循环比较，如果相同，把新的域名替换为空，然后跳出循环
//                if ($ipnew === $ip)
//                {
//
//                    $ipnew = str_replace($ipnew,null,$ipnew);
//                    break;
//                }
//
//
//            }
//            fclose($hand);
////如果新的域名被替换成空，也就不写入新创建的文档中，以此来消除交集
//            if ($ipnew !=null)
//                fwrite($handp,$ipnew."\r\n");
//
//        }
//        fclose($handp);
//        fclose($handnew);


    }

}


class getRurl
{

    public function testUrl($a,$b)
    {
        //  header('Content-type: text/html; charset=utf-8');
//设置成请求等待不受限制，浏览器不会响应等待时间超时
        set_time_limit(0);
        $hand = fopen($a,"r");
        while(!feof($hand))

        {
            //每个请求等3秒
            sleep(3);
            $ip =  trim(fgets($hand));

            $mdhandle = curl_init();
            curl_setopt($mdhandle,CURLOPT_URL,$ip);
            curl_setopt($mdhandle,CURLOPT_RETURNTRANSFER,1);//设置为1，浏览器上不显示，但是有返回值$data,否则相反
            curl_setopt($mdhandle, CURLOPT_HEADER, 1);//显示头信息
            curl_setopt($mdhandle,CURLOPT_NOBODY,1);//不显示body
            curl_setopt($mdhandle, CURLOPT_SSL_VERIFYPEER, false);//不验证https

            $data = curl_exec($mdhandle);

            $getinf = curl_getinfo($mdhandle);
            $re = 'http_respond_code:'.$getinf['http_code'].'----url:'.$getinf['url']."\r\n";
            echo $re.$data."\r\n";
            if(is_dir("sr"))
            {
                $handle2 = fopen("./sr/headcode.txt", "a");
                fwrite($handle2, $re.$data."\r\n");
                fclose($handle2);
            }

            $handle3 = fopen("../resbak/headcode.txt", "a");
            fwrite($handle3, $re.$data."\r\n");
            fclose($handle3);
            curl_close($mdhandle);
//将缓存中数据一条一条取出来,浏览器中可以使用，命令行不行
//            ob_flush();
//            flush();
            $code = $getinf['http_code'];
            $url = $getinf['url']."\r\n";
            if($code === 0 || $code === 404)
            {
                echo "There is no response for this url:".$url."\r\n";
            }
            else
            {
                if(is_dir("sr"))
                {
                    $h = fopen("./sr/newIp.txt","a");
                    fwrite($h,$url);
                    fclose($h);
                }

                $ck = fopen($b,"a");
                fwrite($ck,$url);
                fclose($ck);
            }

            echo "---------------------------------------\r\n";
        }
        fclose($hand);
    }




}

//-m dirname,整个流程工作一遍，进入输入目录整理url，然后将整理好的url和已经检查过的去重，然后再探测80,443端口，输出新的域名
class mainClass extends common
{


    public function mainfun($pjdirname)
    {

        chdir($pjdirname);
        //进入目录后判断有没有sr文件，有就删除sr中的文件后再创建新的sr
        $this ->mkDir("sr");
        $this->collectTxt();
        /*
         * 把temp.txt去重复排序，生成sort-unique.txt，再将它们分门别类放到ip.txt,domain.txt,all.txt中
         * 并对domain.txt 去重复排序，生成sort-unique.txt
         */
        if(is_file("./sr/sort-unique.txt") == 0)
        {
            //   echo "执行getdomain";
            $getdomain = new getdomain();
            $getdomain->getFinalDomain("./sr/temp.txt");
        }


        /*
         * 如果有"../alreadychecked/sr/sort-unique.txt"检查过的域名，才执行compared类,进行过滤
         * 与./sr/sort-unique.txt进行比较，删除检查过的域名,并生成新的filter.txt
         */
        if(is_file("../alreadychecked/sr/sort-unique.txt")==1 && is_file("./sr/filter.txt")==0)
        {
            //     echo "执行com";
            $filter =new compared();
            $b = "../alreadychecked/sr/sort-unique.txt";//以前检查过的域名
            $a = "./sr/sort-unique.txt";//新发现的域名
            $c = "./sr/filter.txt";
            $filter->findDomainCompare($a,$b,$c);
        }

        //如果生成新的过滤后域名filter.txt，就对其进行检查服务是否开启,并生成新的newIp.txt
        if(is_file("./sr/filter.txt") == 1 && is_file("./sr/newIp.txt") == 0  )
        {

            //  echo "执行findRurl";
            $getUrl = new getRurl();
            $a = "./sr/filter.txt";
            $b = "../checkwait/newIp.txt";
            $getUrl->testUrl($a,$b);
        }



    }


}
//-uac 将alreadycheck 和checkwait 中去重排序，分离域名和ip，比如 http://141.160.12.105/，http://141.160.12.105:80/重复了会去除一个

class manageAC extends common
{
    public function ACuniquesort()
    {
        chdir("alreadychecked");
        $this ->mkDir("sr");
        $this->collectTxt();
        $manageurl = new getdomain();
        $manageurl->getFinalDomain("./sr/temp.txt");
        chdir("../");//回到初始 目录，对checkwait目录也执行一遍
        chdir("checkwait");
        $this ->mkDir("sr");
        $this->collectTxt();
        $manageurl->getFinalDomain("./sr/temp.txt");

    }
}

//-ou dirname，包括了-ua,-uc功能，可以指定文件夹进行合并TXT，去重排序分离ip和域名
class unisortDir extends common
{
    public function usDir($dirname)
    {

        chdir($dirname);
        $this->mkDir("sr");
        $this->collectTxt();
        $manageurl = new getdomain();
        $manageurl->getFinalDomain("./sr/temp.txt");
    }
}
// -fac,检查checkwait中的域名是否在alreadychecked中也有common的部分，去掉common的部分在ACfilter中生成 真正新发现的域名
// 和-of,同上，不过是指定文件夹中某个文件对某个文件
class filterAC
{
    public function filterInAC($a,$b,$c)
    {
        $filter =new compared();
        $filter->findDomainCompare($a,$b,$c);
    }
}
//-gf 探测ACfilter中filter.txt的curl响应结果并保存到final/final.txt中
// 和-og 指定文件夹中的txt文件探测curl响应结果，也保存到final/final.txt
class TestUrl
{
    public function testfinurl($a)
    {
        $getUrl = new getRurl();
        $b ="../final/final.txt";
        $getUrl->testUrl($a,$b);
    }

}
//-oc dirname,合并文件夹中 TXT文件到/sr/temp.txt中
class onlyCollected extends common
{
    public function onlycollect($dirname)
    {
        chdir($dirname);
        $this->mkDir("sr");
        $this->collectTxt();
    }
}
//-os dirname filename ,对指定文件夹中TXT文件去重排序生成到/sr/sort-unique.txt中
class onlySortUnied extends common
{
    public function onlysortuni($filename)
    {

        $this->mkDir("sr");
        $this ->sortUnique($filename);
    }
}
//-ocs dirname, 对指定文件夹中的TXT文件合并，并去重排序到/sr/sort-unique.txt中
class onlyCSU extends common
{
    public function onlycs($dirname)
    {
        chdir($dirname);
        $this->mkDir("sr");
        $this->collectTxt();
        $this->sortUnique("./sr/temp.txt");
    }
}
class onlyGetdomain extends common
{
    public function onlygd($filename)
    {
        $this->mkDir("sr");
        $getdomain =new getdomain();
        $getdomain->getFinalDomain($filename);
    }
}

class choseStart extends common
{

    public function start()
    {
        global $argv;
        //先判断第一个input，input之前用空格分隔，$argv在类里需要global
        if (isset($argv[1]))
        {

            $a = $argv[1];
            if ($a == "-i")
            {
                $inidir =new iniDir();
                $inidir->inidir();
            }
            //-m dirname 带两个参数，里面需要再次判断$argv[2]是否为空
            else if($a == "-m" )
            {

                if (isset($argv[2]))
                {
                    $b = $argv[2];
                    if (!is_dir($b))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else
                    {
                        $main = new mainClass();
                        $main->mainfun($b);
                    }
                }
                else
                {
                    $this->help();
                }
            }


            else if ($a == "-ua")
            {
                $dirname ="alreadychecked";
                $unisortdir =new unisortDir();
                $unisortdir->usDir($dirname);
            }
            else if ($a == "-uc")
            {
                $dirname ="checkwait";
                $unisortdir =new unisortDir();
                $unisortdir->usDir($dirname);
            }

            else  if ($a == "-uac")
            {
                $manageAc =new manageAC();
                $manageAc ->ACuniquesort();
            }

            else if ($a == "-fac")
            {
                $b = "./alreadychecked/sr/sort-unique.txt";//以前检查过的域名
                $a = "./checkwait/sr/sort-unique.txt";//新发现的域名.等待检查
                $c = "./ACfilter/filter.txt";
                $filterac =new filterAC();
                $filterac->filterInAC($a,$b,$c);
            }
            //-of 指定文件夹中，对filenameA，和filenameB比较，如果1中在2中也有，就不写入新的txt中，也就是去A-（A交B）
            else if ($a == "-of")
            {
                if(isset($argv[2]))
                {
                    $dirname=$argv[2];
                    if(is_dir($dirname))
                    {
                        chdir($dirname);
                        if(isset($argv[3]) && isset($argv[4]))
                        {
                            $a=$argv[3];
                            $b=$argv[4];
                             if(is_file($a) && is_file($b))
                             {
                                 $this->mkDir("sr");
                                 $c = "./sr/filter.txt";
                                 $filterac =new filterAC();
                                 $filterac->filterInAC($a,$b,$c);

                             }
                            else
                            {
                                echo "The file does not exist\r\n";
                            }
                        }
                        else
                        {
                            $this->help();
                        }
                    }
                    else
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                }
                else
                {
                    $this->help();
                }







            }
            else if ($a == "-gf")
            {
                chdir("ACfilter");
                $a ="./filter.txt";
                $testurl=new TestUrl();
                $testurl->testfinurl($a);
            }

            else if ($a == "-ou")
            {
                if (isset($argv[2]))
                {
                    $dirname = $argv[2];
                    if (!is_dir($dirname))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else {
                        $unisortdir =new unisortDir();
                        $unisortdir->usDir($dirname);
                    }
                }
                else
                {
                    $this->help();
                }
            }
//-oc dirname,合并文件夹中 TXT文件到/sr/temp.txt中
            else if ($a =="-oc")
            {
                if (isset($argv[2]))
                {
                    $dirname = $argv[2];
                    if (!is_dir($dirname))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else {

                        $onlycollec = new onlyCollected();
                        $onlycollec->onlycollect($dirname);
                    }
                }
                else
                {
                    $this->help();
                }

            }
//-os dirname filename ,对指定文件夹中TXT文件去重排序生成到/sr/sort-unique.txt中
            else if ($a =="-os")
            {

                if (isset($argv[2]))
                {
                    $dirname = $argv[2];
                    if (!is_dir($dirname))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else
                    {

                        if (isset($argv[3]))
                        {
                            $filename = $argv[3];
                            chdir($dirname);
                            if (is_file($filename)) {
                               $onlyos=new onlySortUnied();
                                $onlyos->onlysortuni($filename);
                            }
                            else
                            {
                                echo "The input filename does not exist \r\n";
                            }
                        }
                        else
                        {
                            $this->help();
                        }

                    }
                }
                else
                {
                    $this->help();
                }
            }
//-ocs dirname, 对指定文件夹中的TXT文件合并，并去重排序到/sr/sort-unique.txt中
            else if ($a =="-ocs")
            {
                if (isset($argv[2]))
                {
                    $dirname = $argv[2];
                    if (!is_dir($dirname))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else {

                       $onlycs =new onlyCSU();
                        $onlycs->onlycs($dirname);
                    }
                }
                else
                {
                    $this->help();
                }
            }
            //-og dirname filename ,对指定文件夹中分离域名和ip
            else if ($a =="-og")
            {

                if (isset($argv[2]))
                {
                    $dirname = $argv[2];
                    if (!is_dir($dirname))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else
                    {

                        if (isset($argv[3]))
                        {
                            $filename = $argv[3];
                            chdir($dirname);
                            if (is_file($filename)) {
                               $onlygd = new onlyGetdomain();
                                $onlygd->onlygd($filename);

                            }
                            else
                            {
                                echo "The input filename does not exist \r\n";
                            }
                        }
                        else
                        {
                            $this->help();
                        }

                    }
                }
                else
                {
                    $this->help();
                }
            }



            else if ($a =="-ot")
            {

                if (isset($argv[2]))
                {
                    $dirname = $argv[2];
                    if (!is_dir($dirname))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else
                    {

                        if (isset($argv[3]))
                        {
                            $filename = $argv[3];
                            chdir($dirname);
                            if (is_file($filename)) {

                                $testurl =new TestUrl();
                                $testurl->testfinurl($filename);

                            }
                            else
                            {
                                echo "The input filename does not exist \r\n";
                            }
                        }
                        else
                        {
                            $this->help();
                        }

                    }
                }
                else
                {
                    $this->help();
                }
            }

            else  if ($a == "-w")
            {

                if (isset($argv[2]))
                {
                    $dirname = $argv[2];
                    if (!is_dir($dirname))
                    {
                        echo "The input dirname does not exist \r\n";
                    }
                    else {

                        $wvsscan = new wvsScanLog();
                        $wvsscan->scansaves($dirname);
                    }
                }
                else
                {
                    $this->help();
                }

            }
            else
            {
                $this->help();
            }

        }

        else
        {
            $this->help();
        }

    }
    public function help()
    {
        echo "------------------------Miss Input,Underline Is Help Info-----------------------------\r\n";
        echo "---------------------------------------------------------------------------------------\r\n";
        echo "php urlmanager-commonclass.php -i\r\n";
        echo "-i initial,create ini_dir and ini_file\r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -m dirname\r\n";
        echo "-m include whole process for manage url,function A,B,C,D,E\r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -ua\r\n";
        echo "-ua Combine TXT,unique,sort and seperate domain and ip in alreadychecked,function A,B,C \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -uc\r\n";
        echo "-uc Combine TXT,unique,sort and seperate domain and ip in checkwait,function A,B,C \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -uac\r\n";
        echo "-uac Combine TXT,unique,sort and seperate domain and ip in alreadychecked and checkwait,function A,B,C \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -fac\r\n";
        echo "-fac checkwait minus which have common in alreadychecked,function D\r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -gf\r\n";
        echo "-gf get headcode response from ACfilter and output data url to final,function E\r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -w dirname\r\n";
        echo "-w wvscanlog which can find highrisk and abort items,function F\r\n";
        echo "--------------------------------------------------------------------------------------------------------\r\n";
        echo "--------If you want use each particular function in different dir,use underline command--------------\r\n";
        echo "--------------------------------------------------------------------------------------------------------\r\n";
        echo "------dirname also can be(./dir/dir/),filename(./dir/dir/file)----------------\r\n";
        echo "php urlmanager-commonclass.php -oc dirname \r\n";
        echo "-oc Combine TXT in dirname,function A \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -os dirname filename \r\n";
        echo "-os dirname filename,unique and sort in dirname,function B \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -ocs dirname \r\n";
        echo "-ocs Combine TXT,unique,sort in dirname,function A,B \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -ou dirname \r\n";
        echo "-ou Combine TXT,unique,sort and seperate domain and ip in dirname,function A,B,C \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -og dirname filename \r\n";
        echo "-og dirname filename, Combine TXT,seperate domain and ip in dirname,function C \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -of dirname filenameA filenameB \r\n";
        echo "-of,dirname which have file A and B, fileA minus which have common in FileB,function D \r\n";
        echo "----------------------\r\n";
        echo "php urlmanager-commonclass.php -ot dirname filename \r\n";
        echo "-ot dirname filename,get curl response headcode with file in dir,function E \r\n";



    }
}
$chosestart =new choseStart();
$chosestart->start();




/*  initial 初始化创建目录
 * 目录有alreadychecked（已经检测过的域名或ip）checkwait（等待检测的域名或ip）
 * 目录ACfilter 存放checkwait中和alreadychecked有交集的部分去重，也就是这个文件夹中是最终需要等待检测的域名或ip
 * 目录resbak,中存放 headcode.txt中记录响应值 有cookie ，服务器类型，是不是301跳转等
 */

class iniDir
{
    public function inidir()
    {
        $a="alreadychecked";
        $c="checkwait";
        $fac="ACfilter";
        $rb ="resbak";
        $fl = "final";
        $common = new common();
        if(!is_dir($a))
        {
            $common->mkDir($a);
            chdir($a);
            $exmined =fopen("examined.txt","a");
            fclose($exmined);
            $common->mkDir("sr");
            chdir("sr");
            $sort =fopen("sort-unique.txt","a");
            fclose($sort);
            chdir("../../");
        }
        if(!is_dir($c))
        {
            $common->mkDir($c);
            chdir($c);
            $exmined =fopen("newIp.txt","a");
            fclose($exmined);
            chdir("../");
        }
        if(!is_dir($fac))
        {
            $common->mkDir($fac);
            chdir($fac);
            $exmined =fopen("filter.txt","a");
            fclose($exmined);
            chdir("../");
        }
        if(!is_dir($rb))
        {
            $common->mkDir($rb);
            chdir($rb);
            $exmined =fopen("headcode.txt","a");
            fclose($exmined);
            chdir("../");
        }
        if(!is_dir($fl))
        {
            $common->mkDir($fl);
            chdir($fl);
            $exmined =fopen("final.txt","a");
            fclose($exmined);
            chdir("../");
        }
    }
}

//-w dirname 此功能是批量扫描wvs日志，发现高危漏洞的保存到sr文件中，同时扫描完成的输送到alreadychecked中，
//扫描流产的输送到checkwait
class wvsScanLog
{
    public function scansaves($dirname)
    {

//目录控制,进入saves目录，同时创建漏洞文件夹
        $arrsave =$this->dirCtr($dirname);


//进入saves目录后,对log文件计数，哪些不是log文件的不作计数，比如.或者..，控制循环

        $arrc = $this->countDir($arrsave);


        //  echo "前面有！！！代表有高危漏洞，后面有！！！代表扫描完毕没有流产"."\r\n"."</br>";
//  进入saves目录后匹配以ip或者域名开始的文件名
        foreach ($arrsave as $key => $value) {
            //正则匹配，匹配哪些是log文件夹,不是log文件夹的不作处理用continue来控制
            $i=preg_match_all("/^[\w]+\..*/",$value,$matchesv);
            if ($i==0) {
                continue;
            }

            chdir($value); //进入log目录
// $arr2 = scandir("./");//扫描当前目录，做测试用
            // print_r($arr2)."</br>";
            if (is_file("report.html")) {
                $html = file_get_contents("report.html"); //打开report.html,并将ip域名和高危漏洞截取出来

//截取ip
                $ip = $this->catchIp($html);


//判断finish time 有没有The scan was aborted，扫描流产
                $aborted = preg_match_all("/The scan was aborted/", $html, $matches);

//判断risk，high有几个
                $high = $this->catchRisk($html);


//扫描结果 ，前面有！！！代表有高危漏洞，后面后！！！代表扫描完毕没有流产

                $this->scanSr($high, $aborted, $ip);
            }

//控制循环，防止返回上一级目录再循环一次
            $arrc++;

            if ($arrc < count($arrsave)) {
                //返回到上一级目录
                chdir("../");
            } else {
                break;
            }
        }


    }
//执行保存aws扫描日志函数



//目录控制
    private function dirCtr($dirname)
    {
//获取当前目录绝对地址，测试用
        // $curdir=getcwd()."\\saves\\sr";
        // echo $curdir."</br>";
//进入wvs的log目录
        chdir($dirname);

//创建高危漏洞的wvs文件夹，并把所有高危漏洞的wvs文件放到这个目录中并以ip重命名
        if(is_dir("sr")==0)
            mkdir("sr");

//返回saves下的log文件命
        $arrsave = scandir("./");
        return $arrsave;

    }

//进入saves目录后,对log文件计数，哪些不是log文件的不作计数，比如.或者..
    private function countDir($arrsave)
    {

        $k=0;
        foreach ($arrsave as $key => $value) {
            $k = preg_match_all("/^[\w]+\..*/", $value, $matchesv);
            if ($k != 1)
                $k++;
        }
        return $k;
    }

//截取ip
    private function catchIp($html)
    {

        $start = strpos($html, "Scan of http") + 7;  //以Scan of http://为起点，+7，指针跑到h，因为起始位置为0
        $end = strpos($html, "</td><td/>", $start);     //再以td为终点，$start作为连接判断（判断td的开始是哪个，定位作用）
        $ip = substr($html, $start, $end - $start);  //字符串截取，哪开始，长度是多少。
        return $ip;
    }


//判断risk，high有几个
    private function catchRisk($html)
    {
        $starth = strpos($html, ">High</td>") + 50;
        $endh = strpos($html, "</td><td/>", $starth);
        $high = substr($html, $starth, $endh - $starth);
        return $high;
    }


//扫描结果 ，把有高危漏洞的wvslog保存，并把流产的保存以便重新扫描
    private function scanSr($high,$aborted,$ip)
    {
        if ($high == 0 && $aborted == 1) {
            if(is_file("../../checkwait/newIp.txt"))
            {
                $handle = fopen("../../checkwait/newIp.txt", "a");
                fwrite($handle, $ip."\r\n");
                fclose($handle);
            }
            $re = $ip . "----------without HIGHRISK,meantime absorb----------" . "\r\n";
            echo $re;
            //把扫描的全部结果保存
            $handle2 = fopen("../sr/scanresult.txt", "a");
            fwrite($handle2, $re);
            fclose($handle2);

        } else if ($high != 0 && $aborted == 1) {
            // $handle = fopen("../sr/abortresult.txt", "a");
            if(is_file("../../checkwait/newIp.txt"))
            {
                $handle = fopen("../../checkwait/newIp.txt", "a");
                fwrite($handle, $ip."\r\n");
                fclose($handle);
            }

            $re =  $ip . "!!!!!!!!!----------exist HIGHRISK,but absorb----------" . "\r\n";
            echo $re;
            //把扫描的全部结果保存
            $handle2 = fopen("../sr/scanresult.txt", "a");
            fwrite($handle2, $re);
            fclose($handle2);
            //如果有risk，把scan-results.wvs保存到sr目录
            $this-> copyLog($ip);
        } else if ($high == 0 && $aborted == 0) {

            $re = $ip . "----------without HIGHRISK,but scan finish----------!!!!!!" . "\r\n";
            echo $re;
            //把扫描的全部结果保存
            $handle2 = fopen("../sr/scanresult.txt", "a");
            fwrite($handle2, $re);
            fclose($handle2);
            //把扫描完成的保存
            if(is_file("../../alreadychecked/examined.txt"))
            {
                $handle3 = fopen("../../alreadychecked/examined.txt", "a");
                fwrite($handle3, $ip."\r\n");
                fclose($handle3);
            }

        } else {
            $re = $ip . "!!!!!!!!!----------exist HIGHRISK,meantime scan finish----------!!!!!!!!!!" . "\r\n";
            echo $re;
            //把扫描的全部结果保存
            $handle2 = fopen("../sr/scanresult.txt", "a");

            fwrite($handle2, $re);
            fclose($handle2);
            //如果有risk，把scan-results.wvs保存到sr目录
            $this->copyLog($ip);
            //把扫描完成的保存
            if(is_file("../../alreadychecked/examined.txt"))
            {
                $handle3 = fopen("../../alreadychecked/examined.txt", "a");
                fwrite($handle3, $ip."\r\n");
                fclose($handle3);
            }
        }

    }


//把高危的wvs日志保存到sr目录
    private function copyLog($ip)
    {
        $a = str_replace(".","-",$ip);
        $b = str_replace(":","",$a);
        $newip = str_replace("/","",$b).".wvs";
        @copy("scan-results.wvs","../sr/".$newip);

    }
}



?>




