Command:

```jsx

1 git clone https://github.com/Asher459/st_eunomia.git

2 sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm

3 cd src
4 sudo docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
bak:
sudo docker run --rm -it --privileged -v $(pwd):/examples ghcr.io/eunomia-bpf/eunomia-template:latest

5 sudo ./ecli run package.json
```

Tool:

```c
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
$ ./ecli -h
Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args
```
