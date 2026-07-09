# --- ETAP 1: budowanie ---
# Bierzemy obraz z Go, kompilujemy w nim nasz program.
FROM golang:1.22-alpine AS build
# git bywa potrzebny, gdy Go pobiera biblioteki
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
COPY . .
# go mod tidy dociąga bibliotekę pgx i tworzy plik go.sum (lista wersji + sumy kontrolne)
RUN go mod tidy
RUN go build -o /server .

# --- ETAP 2: uruchomienie ---
# Kopiujemy TYLKO gotowy plik wykonywalny do maleńkiego obrazu.
# Dzięki temu finalny kontener jest lekki (bez całego Go w środku).
FROM alpine:latest
COPY --from=build /server /server
EXPOSE 8080
CMD ["/server"]
