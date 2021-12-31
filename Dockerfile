FROM golang

WORKDIR /go/src/vanitytorgen

COPY src/vanitytorgen.go .
COPY go.mod .
COPY go.sum .

RUN go build vanitytorgen.go

ENTRYPOINT ["./vanitytorgen"]

# docker run --rm -d -v "$PWD:/vanitytorgen" vanitytorgen prefix /vanitytorgen
