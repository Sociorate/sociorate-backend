FROM golang

ADD . /usr/sociorate-backend/
WORKDIR /usr/sociorate-backend

RUN go build -gcflags="all=-trimpath=$GOPATH" -asmflags="all=-trimpath=$GOPATH" -ldflags="-s -w" -o ./sociorate-backend.bin

CMD ["./sociorate-backend.bin"]
