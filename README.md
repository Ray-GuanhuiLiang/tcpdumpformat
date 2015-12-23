tcpdumpformat是一个格式化tcpdump输出的工具。

在使用tcpdump查看传输数据的时候有两种方法，一种是使用tcpdump -w把分组数据写到一个文件，然后用wireshark之类的gui工具直接查看，另外一种是使用tcpdump -X来查看输出。

一般我们开发应用的时候有时候只需要关注tcp包的内容部分，ip头和tcp头一般用得不多，然后tcpdump并没有提供工具过滤这两个头。所以就写了这个脚本来处理。

这个工具的使用方法主要是吧tcpdump的16进制输出结果解析，通过解析ip协议的头长度和报文长度，还有tcp协议的头部长度，计算出具体的tcp起始位置，并重新格式化输出。

使用方法：

tcpdump -x ..... | python tcpdumpformat.py

注意，-x参数是必须的，省略号是一个抓取规则，按需输入。
