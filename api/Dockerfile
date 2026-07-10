FROM golang:1.22-alpine AS build
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
COPY . .
RUN go mod tidy
RUN go build -o /server .

FROM alpine:latest
COPY --from=build /server /server
EXPOSE 8080
CMD ["/server"]
