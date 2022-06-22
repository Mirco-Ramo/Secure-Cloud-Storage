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

server_conn.o: $(SERVER_SRC)/server_conn_functions.cpp $(SERVER_SRC)/server_functions.h $(SERVER_SRC)/server_include.h $(SERVER_SRC)/worker.h
	g++ -c $(SERVER_SRC)/server_conn_functions.cpp -o $(SERVER_BLD)/server_conn.o -Wall -Wno-unknown-pragmas

worker_protocol.o: $(SERVER_SRC)/worker_protocol_functions.cpp $(SERVER_SRC)/server_functions.h $(SERVER_SRC)/server_include.h $(SERVER_SRC)/worker.h
	g++ -c $(SERVER_SRC)/worker_protocol_functions.cpp -o $(SERVER_BLD)/worker_protocol.o -Wall -Wno-unknown-pragmas

worker_logic.o: $(SERVER_SRC)/worker_logic_functions.cpp $(SERVER_SRC)/server_functions.h $(SERVER_SRC)/server_include.h $(SERVER_SRC)/worker.h
	g++ -c $(SERVER_SRC)/worker_logic_functions.cpp -o $(SERVER_BLD)/worker_protocol.o -Wall -Wno-unknown-pragmas

#client objects
client_main.o: $(CLIENT_SRC)/client_main.cpp $(CLIENT_SRC)/client_include.h $(CLIENT_SRC)/client_functions.h
	g++ -c $(CLIENT_SRC)/Client_main.cpp -o $(CLIENT_BLD)/Client:main.o -Wall -Wno-unknown-pragmas

client_conn.o: $(CLIENT_SRC)/client_conn_functions.cpp $(CLIENT_SRC)/client_include.h $(CLIENT_SRC)/client_functions.h
	g++ -c $(CLIENT_SRC)/client_conn_functions.cpp -o $(CLIENT_BLD)/client_conn.o -Wall -Wno-unknown-pragmas

client_logic.o: $(CLIENT_SRC)/client_logic_functions.cpp $(CLIENT_SRC)/client_include.h $(CLIENT_SRC)/client_functions.h
	g++ -c $(CLIENT_SRC)/client_logic_functions.cpp -o $(CLIENT_BLD)/client_logic.o -Wall -Wno-unknown-pragmas

client_protocol.o: $(CLIENT_SRC)/client_protocol_functions.cpp $(CLIENT_SRC)/client_include.h $(CLIENT_SRC)/client_functions.h
	g++ -c $(CLIENT_SRC)/client_protocol_functions.cpp -o $(CLIENT_BLD)/client_protocol.o.o -Wall -Wno-unknown-pragmas

#lib objects
crypto_utilities.o: $(LIB_SRC)/crypto_utilities.cpp $(LIB_SRC)/buffers.h $(LIB_SRC)/common_functions.h $(LIB_SRC)/common_parameters.h $(LIB_SRC)/struct_message.h
	g++ -c $(LIB_SRC)/crypto_utilities.cpp -o $(LIB_BLD)/crypto_utilities.o -Wall -Wno-unknown-pragmas

communication_utilities.o: $(LIB_SRC)/communication_utilities.cpp $(LIB_SRC)/buffers.h $(LIB_SRC)/common_functions.h $(LIB_SRC)/common_parameters.h $(LIB_SRC)/struct_message.h
	g++ -c $(LIB_SRC)/communication_utilities.cpp -o $(LIB_BLD)/communication_utilities.o -Wall -Wno-unknown-pragmas

#remove object files
clean:
	@rm -f $(SERVER_BLD)/*.o
	@rm -f $(CLIENT_BLD)/*.o
	@rm -f $(LIB_BLD)/*.o