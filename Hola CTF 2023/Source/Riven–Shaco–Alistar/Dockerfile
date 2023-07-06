FROM ubuntu:22.04

RUN apt-get update && apt-get install python3 python3-pip -y
RUN pip3 install pycryptodome

RUN useradd -d /home/holactf -m -p holactf -s /bin/bash holactf
RUN echo "holactf:holactf" | chpasswd

WORKDIR /home/holactf

COPY ./pro/* ./

EXPOSE 2706

CMD ["python3", "chal.py"]