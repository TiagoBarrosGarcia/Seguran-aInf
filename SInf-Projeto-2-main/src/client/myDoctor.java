package client;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Scanner;

import server.myDoctorServer;

public class myDoctor {
	private static ObjectInputStream inStream = null;
	private static ObjectOutputStream outStream = null;
	private static BufferedOutputStream buffOutStream = null;
	private static BufferedInputStream buffInStream = null;

	private static Scanner sc = new Scanner(System.in);

	public static void main(String[] args) throws Exception {
		createDir();

		String userId = null;
		String[] hostPort = null;
		String password = null;

		String operation = null;
		String sUserId = null;
		String sUserName = null;
		String sUserPass = null;
		String sUserType = null;

		String fileName = null;

		Boolean passCheck = false;

		int i = 0;
		while (i < args.length) {

			if (args[i].equals("-u")) {
				userId = args[i + 1];
			} else if (args[i].equals("-a")) {
				hostPort = args[i + 1].split(":");
			} else if (args[i].equals("-p")) {
				passCheck = true;
				password = args[i + 1];
			} else if (args[i].equals("-c")) {
				operation = args[i];
				sUserId = args[i + 1];
				sUserName = args[i + 2];
				sUserPass = args[i + 3];
				sUserType = args[i + 4];

			} else if (args[i].equals("-mu")) {
				operation = args[i];
			} else if (args[i].equals("-md")) {
				operation = args[i];
			} else if (args[i].equals("-mx")) {
				operation = args[i];
				sUserId = args[i + 1];
			} else if (args[i].equals("-d")) {
				operation = args[i];
				fileName = args[i + 1];
			} else if (args[i].equals("-du")) {
				operation = args[i];
				fileName = args[i + 1];
				sUserId = args[i + 2];
			} else if (args[i].equals("-su")) {
				operation = args[i];
				fileName = args[i + 1];
				sUserId = args[i + 2];
			}

			i++;
		}

		if (!passCheck) {
			Boolean flag = true;
			System.out.println("Password is missing!");
			while (flag) {
				System.out.println("Insert password: ");
				password = sc.nextLine();
				if (password != " " || password != "") {
					flag = false;
				}
			}
		}

		Socket sockDocter = new Socket(hostPort[0], Integer.parseInt(hostPort[1]));

		System.out.println(sockDocter.getLocalPort());
		ObjectInputStream inStream = new ObjectInputStream(sockDocter.getInputStream());
		ObjectOutputStream outStream = new ObjectOutputStream(sockDocter.getOutputStream());
		// -c
		if (operation.equals("-c")) {

			outStream.writeObject(operation);
			outStream.writeObject(userId);
			outStream.writeObject(password);

			outStream.writeObject(sUserId);
			outStream.writeObject(sUserName);
			outStream.writeObject(sUserPass);
			outStream.writeObject(sUserType);

			System.out.println("O utilizador " + sUserName + " com o ID " + sUserId + " vai ser criado");

			Boolean created = (Boolean) inStream.readObject();

			if (created) {
				System.out.println("O utilizador " + sUserName + " foi criado");

				// Criação da diretoria do user
				Path path = Paths.get("./Cliente/" + sUserId);
				Files.createDirectory(path);

				String[] user = new String[4];

				// Criação de keystore
//				genKeyStore(user);
//				
//				// Movimentação da keystore para a pasta do cliente
//				Path fileToMovePath = Paths.get("./keystore." + sUserId);
//			    Path targetPath = Paths.get("./Cliente/" + sUserId + "/");
//			    Files.move(fileToMovePath, targetPath);
			} else {
				String response = (String) inStream.readObject();
				System.out.println(response);
			}
			// -mu
		} else if (operation.equals("-mu")) {
			outStream.writeObject(operation);
			outStream.writeObject(userId);
			outStream.writeObject(password);

			Boolean success = (Boolean) inStream.readObject();

			if (success) {
				ArrayList<String> usersmu = (ArrayList<String>) inStream.readObject();
				for (String user : usersmu) {
					System.out.println(user);
				}
			} else {
				String response = (String) inStream.readObject();
				System.out.println(response);
			}

			// -md
		} else if (operation.equals("-md")) {
			outStream.writeObject(operation);
			outStream.writeObject(userId);
			outStream.writeObject(password);

			Boolean response = (Boolean) inStream.readObject();
			if (response) {
				ArrayList<String> files = (ArrayList<String>) inStream.readObject();
				for (String file : files) {
					System.out.println(file);
				}
			} else {
				String response2 = (String) inStream.readObject();
				System.out.println(response2);

			}
			// -mx
		} else if (operation.equals("-mx")) {
			outStream.writeObject(operation);
			outStream.writeObject(userId);
			outStream.writeObject(password);

			outStream.writeObject(sUserId);

			Boolean response = (Boolean) inStream.readObject();
			if (response) {
				ArrayList<String> files = (ArrayList<String>) inStream.readObject();
				for (String file : files) {
					System.out.println(file);
				}
			} else {
				String response2 = (String) inStream.readObject();
				System.out.println(response2);

			}
			// -d
		} else if (operation.equals("-d")) {
			outStream.writeObject(operation);
			outStream.writeObject(userId);
			outStream.writeObject(password);
			outStream.writeObject(fileName);

			Boolean response = (Boolean) inStream.readObject();

			if (response) {
				ArrayList<String> files = (ArrayList<String>) inStream.readObject();

				for (String file : files) {
					// Filtrar apenas ficheiros que se quer
					if (file.equals(fileName) || file.contains("signed")) {

						String newFile = "./Cliente/" + userId + "/" + file;

						buffOutStream = new BufferedOutputStream(new FileOutputStream(newFile));

						byte[] buffer = new byte[1024];

						Long size = (Long) inStream.readObject();

						int x = 0;
						int temp = size.intValue();

						while (temp > 0) {
							x = inStream.read(buffer, 0, temp > 1024 ? 1024 : temp);
							buffOutStream.write(buffer, 0, x);
							temp -= x;
						}

						buffOutStream.close();
					}
				}

				System.out.println("O ficheiro " + fileName + " foi recebido pelo cliente.");

				if (verifySign(userId, files)) {
					System.out.println("Ficheiro " + fileName + " válido!");

					// Apagar ficheiro com assinatura
					deleteSigned(userId);

				} else {
					System.out.println("Ficheiro " + fileName + " não válido!");
				}

			} else {
				String response2 = (String) inStream.readObject();
				System.out.println(response2);
			}
			// -du
		} else if (operation.equals("-du")) {
			outStream.writeObject(operation);
			outStream.writeObject(userId);
			outStream.writeObject(password);
			outStream.writeObject(sUserId);

			outStream.writeObject(fileName);

			Boolean response = (Boolean) inStream.readObject();

			if (response) {
				ArrayList<String> files = (ArrayList<String>) inStream.readObject();

				for (String file : files) {
					// Filtrar apenas ficheiros que se quer
					if (file.equals(fileName) || file.contains("signed")) {

						String newFile = "./Cliente/" + userId + "/" + file;

						buffOutStream = new BufferedOutputStream(new FileOutputStream(newFile));

						byte[] buffer = new byte[1024];

						Long size = (Long) inStream.readObject();

						int x = 0;
						int temp = size.intValue();

						while (temp > 0) {
							x = inStream.read(buffer, 0, temp > 1024 ? 1024 : temp);
							buffOutStream.write(buffer, 0, x);
							temp -= x;
						}

						buffOutStream.close();
					}
				}

				System.out.println("O ficheiro " + fileName + " foi recebido pelo cliente.");

				if (verifySign(userId, files)) {
					System.out.println("Ficheiro " + fileName + " válido!");
					// Apagar ficheiro com assinatura
					deleteSigned(userId);
				} else {
					System.out.println("Ficheiro " + fileName + " não válido!");
				}

			} else {
				String response2 = (String) inStream.readObject();
				System.out.println(response2);
			}
			// -su
		} else if (operation.equals("-su")) {
			outStream.writeObject(operation);
			outStream.writeObject(userId);
			outStream.writeObject(password);
			outStream.writeObject(sUserId);
			outStream.writeObject(fileName);

			String signFileName = digitalSign(userId, fileName);

			if (signFileName.equals("")) {
				System.out.println("O ficheiro não foi assinado");

			} else {
				ArrayList<String> files = new ArrayList<String>();

				files.add(fileName);
				files.add(signFileName);

				outStream.writeObject(files);

				for (String file : files) {
					// Primeiro ficheiro original

					File currentFile = new File("./Cliente/" + userId + "/" + file);

					Long size = (Long) currentFile.length();

					outStream.writeObject(size);

					byte[] buffer = new byte[1024];

					buffInStream = new BufferedInputStream(new FileInputStream(currentFile));

					int x = 0;
					while ((x = buffInStream.read(buffer, 0, 1024)) > 0) {
						outStream.write(buffer, 0, x);
					}

					buffInStream.close();
				}

			}

			Boolean response = (Boolean) inStream.readObject();

			if (response) {
				System.out.println("O ficheiro " + fileName
						+ " foi enviado para o servidor e ficou associado ao utilizador com o id " + sUserId);
				// Apagar ficheiro com assinatura
				deleteSigned(userId);
			} else {
				String response2 = (String) inStream.readObject();
				System.out.println(response2);
			}

		}

		outStream.close();
		inStream.close();

		sockDocter.close();

	}

	/**
	 * Cria uma diretoria para guardar os ficheiros descarregados dos clientes
	 * 
	 * @throws IOException
	 */
	public static void createDir() throws IOException {
		Path path = Paths.get("./Cliente/");
		boolean dir = Files.isDirectory(path);

		if (!dir) {
			Files.createDirectory(path);
		} else {
			System.out.println("Pasta do cliente já existe!");
		}
	}

	public static void genKeyStore(String[] user) {
		String command = "keytool -genkeypair -alias " + user[0]
				+ " -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore." + user[0] + "-dname CN=" + user[1]
				+ "-dname OU=Hospital -dname O=FCUL -dname L=Lisboa -dname ST=LS -dname C=PT" + "-keypass " + user[2];

		System.out.println(command);
		String[] cmd = command.split(" ");
		try {
			Runtime.getRuntime().exec(cmd);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static String digitalSign(String userId, String fileName) throws Exception {
		String name = "signed." + userId;

		System.out.println("Indique o alias: ");
		String alias = sc.nextLine();

		System.out.println("Indique a password da keystore: ");
		String password = sc.nextLine();

		// Obter a chave privada do user
		FileInputStream kFile = new FileInputStream("./Cliente/" + userId + "/keystore." + userId);
		KeyStore kStore = KeyStore.getInstance("PKCS12");
		kStore.load(kFile, password.toCharArray()); // password da keystore
		Key privateKey = kStore.getKey(alias, password.toCharArray());

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign((PrivateKey) privateKey);
		// sig.initVerify(certificate); // para verificar assinatura

		FileInputStream fis;
		FileOutputStream fos;

		fis = new FileInputStream("./Cliente/" + userId + "/" + fileName); // Ficheiro para assinar e cifrar
		fos = new FileOutputStream("./Cliente/" + userId + "/" + name); // Ficheiro já assinado e cifrado

		byte[] b = new byte[2048];
		int i = fis.read(b);
		while (i != -1) {
			sign.update(b, 0, i);
			i = fis.read(b);
		}

		fos.write(sign.sign());
		fos.close();
		fis.close();

		File signFile = new File("./Cliente/" + userId + "/" + name);
		if (signFile.exists()) {
			return name;
		} else {
			return "";
		}

	}

	public static Boolean verifySign(String userId, ArrayList<String> files) throws Exception {
		String origFile = null;
		String signFile = null;
		String signUserId = null;

		System.out.println("Indique a password da keystore: ");
		String password = sc.nextLine();

		for (String file : files) {
			if (file.contains("signed")) {
				signFile = file;
				signUserId = file.split("\\.")[1];
			} else {
				origFile = file;
			}
		}

		// Obter a chave publica do user que assinou
		FileInputStream kFile = new FileInputStream("./Cliente/" + userId + "/keystore." + userId); // store com as
																									// chaves publicas
		KeyStore kStore = KeyStore.getInstance("PKCS12");
		kStore.load(kFile, password.toCharArray()); // password da keystore

		Certificate cert = kStore.getCertificate("servidor");

		Signature sign = Signature.getInstance("SHA256withRSA");

		sign.initVerify(cert); // para verificar assinatura

		FileInputStream fis;
		FileInputStream fsig;

		fis = new FileInputStream("./Cliente/" + userId + "/" + origFile); // Ficheiro para assinar e cifrar
		fsig = new FileInputStream("./Cliente/" + userId + "/" + signFile); // Ficheiro já assinado e cifrado

		byte[] b = new byte[2048];
		int i = fis.read(b);
		while (i != -1) {
			sign.update(b, 0, i);
			i = fis.read(b);
		}

		byte[] signature = new byte[256];
		fsig.read(signature);

		fsig.close();
		fis.close();

		if (sign.verify(signature)) {
			return true;
		} else {
			return false;
		}

	}

	public static void deleteSigned(String userId) {
		File dir = new File("./Cliente/" + userId);
		File[] directoryListing = dir.listFiles();
		if (directoryListing.length > 0) {
			for (File child : directoryListing) {
				if (child.getName().contains("signed")) {
					child.delete();
				}

			}
		}

	}

}
