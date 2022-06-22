SOURCE = Source
BUILD = Build

SERVER_SRC = $(SOURCE)/Server
CLIENT_SRC = $(SOURCE)/Client
LIB_SRC = $(SOURCE)/Common_Libs

SERVER_BLD = $(BUILD)/Server
CLIENT_BLD = $(BUILD)/Client
LIB_BLD = $(BUILD)

all: server client clean
	$(info Ready !)

env:
	@mkdir -p $(BUILD)
	@mkdir -p $(SERVER_BLD)
	@mkdir -p $(CLIENT_BLD)
	@mkdir -p $(LIB_BLD)

#build server
server: server_main.o server_conn.o worker_protocol.o worker_logic.o common_libs
	g++  $(SERVER_BLD)/ServerMain.o $(SERVER_BLD)/server_conn.o $(SERVER_BLD)/worker_protocol.o $(SERVER_BLD)/worker_logic.o  $(LIB_BLD)/crypto_utilities.o $(LIB_BLD)/communication_utilities.o -o $(SERVER_BLD)/Server -lcrypto -pthread -Wall -Wno-unknown-pragmas

#build client
client: client_main.o client_conn.o client_logic.o client_protocol.o common_libs
	g++ $(CLIENT_BLD)/client_main.o $(CLIENT_BLD)/client_conn.o $(CLIENT_BLD)/client_logic.o $(CLIENT_BLD)/client_protocol.o $(LIB_BLD)/communication_utilities.o $(LIB_BLD)/crypto_utilities.o -o $(CLIENT_BLD)/Client -lcrypto -Wall -Wno-unknown-pragmas

#build shared lib
common_libs: communication_utilities.o crypto_utilities.o

#server objects
server_main.o: $(SERVER_SRC)/server_main.cpp $(SERVER_SRC)/server_functions.h $(SERVER_SRC)/server_include.h
	g++ -c $(SERVER_SRC)/ServerMain.cpp -o $(SERVER_BLD)/ServerMain.o -Wall -Wno-unknown-pragmas

chat_functions.o: $(SERVER_SRC)/chat_functions.cpp $(SERVER_SRC)/header_server.h
	g++ -c $(SERVER_SRC)/chat_functions.cpp -o $(SERVER_BLD)/chat_functions.o -Wall -Wno-unknown-pragmas

OnlineUsers.o: $(SERVER_SRC)/OnlineUsers.cpp $(SERVER_SRC)/OnlineUsers.h $(SERVER_SRC)/header_server.h
	g++ -c $(SERVER_SRC)/OnlineUsers.cpp -o $(SERVER_BLD)/OnlineUsers.o -Wall -Wno-unknown-pragmas

server_command_functions.o: $(SERVER_SRC)/server_command_functions.cpp $(SERVER_SRC)/header_server.h
	g++ -c $(SERVER_SRC)/server_command_functions.cpp -o $(SERVER_BLD)/server_command_functions.o -Wall -Wno-unknown-pragmas

server_utility.o: $(SERVER_SRC)/server_utility.cpp $(SERVER_SRC)/header_server.h
	g++ -c $(SERVER_SRC)/server_utility.cpp -o $(SERVER_BLD)/server_utility.o -Wall -Wno-unknown-pragmas

user_handling.o: $(SERVER_SRC)/user_handling.cpp $(SERVER_SRC)/header_server.h
	g++ -c $(SERVER_SRC)/user_handling.cpp -o $(SERVER_BLD)/user_handling.o -Wall -Wno-unknown-pragmas

#client objects
ClientMain.o: $(CLIENT_SRC)/ClientMain.cpp $(CLIENT_SRC)/header_client.h
	g++ -c $(CLIENT_SRC)/ClientMain.cpp -o $(CLIENT_BLD)/ClientMain.o -Wall -Wno-unknown-pragmas

client_keys_exchange.o: $(CLIENT_SRC)/client_keys_exchange.cpp $(CLIENT_SRC)/header_client.h
	g++ -c $(CLIENT_SRC)/client_keys_exchange.cpp -o $(CLIENT_BLD)/client_keys_exchange.o -Wall -Wno-unknown-pragmas

client_utility.o: $(CLIENT_SRC)/client_utility.cpp $(CLIENT_SRC)/header_client.h
	g++ -c $(CLIENT_SRC)/client_utility.cpp -o $(CLIENT_BLD)/client_utility.o -Wall -Wno-unknown-pragmas

client_command_functions.o: $(CLIENT_SRC)/client_command_functions.cpp $(CLIENT_SRC)/header_client.h
	g++ -c $(CLIENT_SRC)/client_command_functions.cpp -o $(CLIENT_BLD)/client_command_functions.o -Wall -Wno-unknown-pragmas

communication_utility.o: $(CLIENT_SRC)/communication_utility.cpp $(CLIENT_SRC)/header_client.h
	g++ -c $(CLIENT_SRC)/communication_utility.cpp -o $(CLIENT_BLD)/communication_utility.o -Wall -Wno-unknown-pragmas

#shared objects
communication_utilities.o: $(LIB_SRC)/communication_utilities.cpp $(LIB_SRC)/common_parameters.h $(LIB_SRC)/common_functions.h $(LIB_SRC)/struct_message.h $(LIB_SRC)/buffers.h
	g++ -c $(LIB_SRC)/communication_utilities.cpp -o $(LIB_BLD)/communication_utilities.o -Wall -Wno-unknown-pragmas

crypto_suite.o: $(LIB_SRC)/crypto_suite.cpp $(LIB_SRC)/crypto_suite.h $(LIB_SRC)/header.h
	g++ -c $(LIB_SRC)/crypto_suite.cpp -o $(LIB_BLD)/crypto_suite.o -Wall -Wno-unknown-pragmas

#remove object files
clean:
	@rm -f $(SERVER_BLD)/*.o
	@rm -f $(CLIENT_BLD)/*.o
	@rm -f $(LIB_BLD)/*.o