import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;



public class Servidor {
	public static int PUERTO = 8080;
	public static int idthread ;


	public static void main(String[] args) throws IOException {
		idthread = 0;
		ServerSocket ss = null;
		boolean continuar = true;
		// defina variable para contar e identificar los threads
		try {
			ss = new ServerSocket(PUERTO);
		} catch (IOException e) {
			System.err.println("No pudo crear socket en el puerto:" + PUERTO);
			System.exit(-1);
		}
		while (continuar) {
		
			
			ThreadServidor h = new ThreadServidor(ss.accept(), PUERTO);
			
			h.start();
			// incremente identificador de thread
			idthread++;

		}
		ss.close();
	}


}
