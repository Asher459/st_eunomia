Command:

```jsx

1 git clone https://github.com/Asher459/st_eunomia.git
//复制项目地址

2 sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
//安装相应依赖环境

3 cd src
//进入源代码

4 sudo docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
//编译源代码
bak:
sudo docker run --rm -it --privileged -v $(pwd):/examples ghcr.io/eunomia-bpf/eunomia-template:latest

5 sudo ./ecli run package.json
//执行配置文件
```

Tool:

```c
如果提示无ecli工具，可以用下列命令下载：
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
$ ./ecli -h
Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args
```
