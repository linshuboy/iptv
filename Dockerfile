From  python:3.10
COPY ./iptv2m3u.py /app/iptv2m3u.py
COPY ./run.sh /app/run.sh
WORKDIR /app
RUN chmod +x ./run.sh
RUN pip3 install requests
RUN pip3 install scapy
CMD ["/bin/bash","/app/run.sh"]
