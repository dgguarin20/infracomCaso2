

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;

public class protocolo {

	public void procesar(BufferedReader pIn,PrintWriter pOut) throws IOException {
		
		
		String inputLine, outputLine;
		int estado = 0;

		while (estado < 3 && (inputLine = pIn.readLine()) != null) {
		switch (estado) {
		case 0:
		if (inputLine.equalsIgnoreCase("HOLA")) {
		outputLine = "LISTO";
		estado++;
		} else {
		outputLine = "ERROR-EsperabaHola";
		estado = 0;
		}
		break;
		case 1:
		try {
		int val = Integer.parseInt(inputLine);
		val++;
		outputLine = "" + val;
		estado++;
		} catch (Exception e) {
		outputLine = "ERROR-EnArgumentoEsperado";
		estado = 0;
		}
		break;
		case 2:
		if (inputLine.equalsIgnoreCase("OK")) {
		outputLine = "ADIOS";
		estado++;
		} else {
		outputLine = "ERROR-EsperabaOK";
		estado = 0;
		}
		break;
		default:
		outputLine = "ERROR";
		estado = 0;
		break;
		}
		}
		}
}
