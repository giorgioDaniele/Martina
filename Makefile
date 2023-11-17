CC = gcc
CFLAGS =  -g -Wall
CLIENT_OBJ_FILES = client/main.o
SERVER_OBJ_FILES = server/main.o

CLIENT_TARGET = client_prog
SERVER_TARGET = server_prog

all: $(CLIENT_TARGET) $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_OBJ_FILES)
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) $(CLIENT_OBJ_FILES) -lssl -lcrypto
	rm -f $(CLIENT_OBJ_FILES)
	chmod a+x $(CLIENT_TARGET)

$(SERVER_TARGET): $(SERVER_OBJ_FILES)
	$(CC) $(CFLAGS) -o $(SERVER_TARGET) $(SERVER_OBJ_FILES) -lssl -lcrypto
	rm -f $(SERVER_OBJ_FILES)
	chmod a+x $(SERVER_TARGET)

clean:
	rm -f $(CLIENT_TARGET) *~
	rm -f $(SERVER_TARGET) *~