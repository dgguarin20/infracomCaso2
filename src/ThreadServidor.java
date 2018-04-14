

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class ThreadServidor extends Thread{
	// atributo socket
	private Socket sktCliente = null;
	public int idLocal ;

	// defina un atributo identificador local de tipo int
	public ThreadServidor(Socket pSocket,int pId) {
		// asigne el valor a los atributos correspondientes
		
		sktCliente= pSocket;
		idLocal=pId;

	}



	public void run() {
		
		System.out.println("Inicio de nuevo thread." + idLocal);
		try {
			PrintWriter escritor = new PrintWriter(sktCliente.getOutputStream(), true);
			BufferedReader lector = new BufferedReader(new InputStreamReader(sktCliente.getInputStream()));
			procesar(lector,escritor);
			escritor.close();
			lector.close();
			sktCliente.close();
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	public void start()
	{		
		run();
		
	}
	
	public void procesar(BufferedReader pIn,PrintWriter pOut) throws IOException {


		String inputLine, outputLine;
		int estado = 0;
		ArrayList bytes = new ArrayList();
		ArrayList codigo = new ArrayList();
		ArrayList nuevo = new ArrayList();
		while (estado < 3 && (inputLine = pIn.readLine()) != null) {

			switch (estado) {
			case 0:

				if (inputLine.equalsIgnoreCase("HOLA")) {
					outputLine = "INICIO";
					pOut.println(outputLine);
					estado++;
					
				} else {
					outputLine = "ERROR-EsperabaHola";
					estado = 0;
				}
				break;
			case 1:
				String[] a = inputLine.split(":");
				for(int i = 1; i<a.length; i++)
				{
				if (a[i].equalsIgnoreCase("AES")||a[i].equalsIgnoreCase("BLOWFISH")||a[i].equalsIgnoreCase("RSA")||a[i].equalsIgnoreCase("HMACMD5")||a[i].equalsIgnoreCase("HMACSHA1")||a[i].equalsIgnoreCase("HMACSHA256") ) {
					outputLine = "OK";
					codigo.add(a[i]);
					pOut.println(outputLine);
					estado++;
					
				} else {
					outputLine = "ERROR";
					
					codigo = nuevo;
					pOut.println(outputLine);
					estado = 0;
				}
				}
				break;
			case 2:
				if (inputLine.equalsIgnoreCase("CERTCLNT")) {
					
					estado++;
				}
				else
				{
					outputLine = "ERROR";
				
					codigo = nuevo;
					pOut.println(outputLine);
					estado = 0;
				}

				break;
			case 3:
				if(inputLine != null)
				{
					bytes.add(inputLine);
					outputLine = "OK";
					pOut.println(outputLine);
					estado++;
					
				}
				else
				{
					outputLine = "ERROR";
					codigo = nuevo;
					pOut.println(outputLine);
					estado = 0;
				}
					
				break;
			case 4:
				outputLine = "CERTSRV";
				pOut.println(outputLine);
				estado++;
				break;
			case 5:
				java.security.cert.X509Certificate cert;
				try {
					cert = cambiobytes();
					byte[] mybyte = cert.getEncoded();
					sktCliente.getOutputStream().write(mybyte);
					sktCliente.getOutputStream().flush();
					estado++;
					break;
					
				} catch (NoSuchAlgorithmException | CertificateEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}


				
				break;
			default:
				outputLine = "ERROR";
				estado = 0;
				break;
			}
		}
	}


	
	
private static X509Certificate cambiobytes() throws NoSuchAlgorithmException {
		
	
		
		KeyPairGenerator generadorKey = KeyPairGenerator.getInstance("RSA");
		generadorKey.initialize(1024, new SecureRandom());
		KeyPair keypair = generadorKey.generateKeyPair();
		
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keypair.getPublic().getEncoded());
		BigInteger a = BigInteger.valueOf(new Long(123456723));
		X500Name nombre = new X500Name("Cliente");
		Date antes = new Date(System.currentTimeMillis());
		Date Despues = new Date(System.currentTimeMillis()+(1000L*3600*24*365*100));
		X500Name nombre2 = new X500Name("Servidor");
		X509v3CertificateBuilder myX509v3CertBuilder = new X509v3CertificateBuilder(nombre, a, antes, Despues, nombre2, publicKeyInfo);
		

		try {
			ContentSigner signer;
			signer = new JcaContentSignerBuilder("Sha256withRSA").build(keypair.getPrivate());
			X509CertificateHolder certHolder = myX509v3CertBuilder.build(signer);
			X509Certificate cert = (new JcaX509CertificateConverter()).getCertificate(certHolder);
			return cert;
			
		} catch (CertificateException | OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;

		
		

	}
}
