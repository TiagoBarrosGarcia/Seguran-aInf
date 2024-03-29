package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class myDoctorServer {

	private static Scanner sc = new Scanner(System.in);
	private static int port;
	private static String passFile;
	private static ArrayList<String> usersmu;

	public myDoctorServer(int port) throws Exception {
		myDoctorServer.port = port;
		try {
			createDir();
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
		checkFile();
		startServer();

	}

	/**
	 * Getter para a porta do servidor
	 * 
	 * @return porta do servidor
	 */
	public int getPort() {
		return myDoctorServer.port;
	}

	/**
	 * Getter do ficheiro de de passwords
	 * 
	 * @return o nome do ficheiro de passwords do sistema
	 */
	public static String getPassFile() {
		return passFile;
	}

	/**
	 * Setter do ficheiro de passwords
	 * 
	 * @param nome do ficheiro de passwords
	 */
	public static void setPassFile(String passFile) throws Exception {
		myDoctorServer.passFile = passFile;
	}

	public static void main(String[] args) throws Exception {

		if (args[0] == "" || args[0] == " ") {
			Boolean flag = true;
			System.out.println("Please insert server port!");
			while (flag) {
				System.out.println("input>");
				String port = sc.nextLine();
				if (port != " " || port != "") {
					flag = false;
				}
				myDoctorServer server = new myDoctorServer(Integer.parseInt(args[0]));
			}
		} else {
			myDoctorServer server = new myDoctorServer(Integer.parseInt(args[0]));
		}

	}

	/**
	 * Função que irá inicializar o servidor e as respectivas threads
	 */
	public void startServer() {

		ServerSocket srvSocket = null;
		try {
			srvSocket = new ServerSocket(this.getPort());
			System.out.println("Server is running on PORT: " + String.valueOf(port));
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		while (true) {
			try {
				Socket thrSocket = srvSocket.accept();
				ServerThread newServerThread = new ServerThread(thrSocket);
				newServerThread.start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}

	}

	/**
	 * Função que verifica ou cria o ficheiro de passwords
	 */
	public void checkFile() throws Exception {
		try {
			File file = new File("passwords.txt");
			if (file.createNewFile()) {
				myDoctorServer.setPassFile(file.getName());
				createAdminUser();
			} else {
				System.out.println("File loaded!");
			}
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}

	public static void sinteseFile(String str) throws NoSuchAlgorithmException, IOException {
		String data = str;

		FileOutputStream fos = new FileOutputStream("passwords.txt");
		MessageDigest md = MessageDigest.getInstance("SHA");
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		byte buf[] = data.getBytes();
		byte hash[] = md.digest(buf);
		oos.writeObject(data);
		oos.writeObject(hash);
		fos.close();

	}

	public static String readSintese() {
		String data = null;
		try {
			FileInputStream fis = new FileInputStream("passwords.txt");
			ObjectInputStream ois = new ObjectInputStream(fis);
			Object o = ois.readObject();
			if (!(o instanceof String)) {
				System.out.println("Unexpected data in file");
				System.exit(-1);

			}
			data = (String) o;

		} catch (Exception e) {
			System.out.println(e);
		}
		return data;
	}

	public static void updateSintese(String newData) {

		try {
			FileInputStream fis = new FileInputStream("passwords.txt");
			ObjectInputStream ois = new ObjectInputStream(fis);
			Object o = ois.readObject();
			if (!(o instanceof String)) {
				System.out.println("Unexpected data in file");
				System.exit(-1);

			}

			String data = (String) o;
			String newContent = data + newData;

			FileOutputStream fos = new FileOutputStream("passwords.txt");
			MessageDigest md = MessageDigest.getInstance("SHA");
			ObjectOutputStream oos = new ObjectOutputStream(fos);

			byte buf[] = newContent.getBytes();
			md.update(buf);

			oos.writeObject(newContent);
			oos.writeObject(md.digest());
			fos.close();

		} catch (Exception e) {
			System.out.println(e);
		}
		verifyFile();

	}

	public static void verifyFile() {

		try {
			FileInputStream fis = new FileInputStream("passwords.txt");
			ObjectInputStream ois = new ObjectInputStream(fis);
			Object o = ois.readObject();
			if (!(o instanceof String)) {
				System.out.println("error");
				System.exit(-1);
			}
			String data = (String) o;
			byte origDig[] = (byte[]) ois.readObject(); // devia-se validar “origDig” como em “data”
			MessageDigest md = MessageDigest.getInstance("SHA");
			if (MessageDigest.isEqual(md.digest(data.getBytes()), origDig)) { // método isEqual faz apenas uma
																				// comparação byte a byte

				System.out.println("Ficheiro de passwords valido!");
			}

			else {
				System.out.println("File was corrupted");
			}

			fis.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Função que cria o utilizador admin e o escreve no ficheiro de passwords
	 */
	public void createAdminUser() throws Exception {
		int id = 1;
		String name = "Administrador_base";
		String type = "admin";

		SecureRandom random = new SecureRandom();
		byte[] saltArray = new byte[8];
		random.nextBytes(saltArray);

		String salt = Base64.getEncoder().encodeToString(saltArray);

		System.out.println("Insert admin password: ");
		String password = sc.nextLine();

		String hashedPassword = encryptPass(password, saltArray);

		String[] arr = new String[5];
		arr[0] = String.valueOf(id);
		arr[1] = name;
		arr[2] = hashedPassword;
		arr[3] = type;
		arr[4] = salt;

		// Criação de keystore
		genKeyStore(arr);

		StringBuilder data = new StringBuilder();
		int len = arr.length;
		for (int i = 0; i < len; i++) {
			data.append(arr[i] + ";");
		}
		data.append("\n");

		try {
			sinteseFile(data.toString());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Password file and keyStore created for admin user!");

	}

	/**
	 * Verifica se o utilizador dado existe no ficheiro de passwords e se a password
	 * da corresponde à do ficheiro
	 * 
	 * @param user     ID do user
	 * @param password Password do user
	 * @return true em caso de existir e password igual ou falso caso contrario
	 */
	public static Boolean findUser(String user, String password) throws Exception {
		Boolean found = false;

		String[] users = getUsersArray(readSintese());
		int len = users.length;
		for (int i = 0; i < len; i++) {
			String[] userArray = users[i].split(";");
			if (userArray[0].equals(user)) {
//				System.out.println(userArray[0] + ":" + userArray[2]);
				if (validateEncryptPass(password, userArray[2], userArray[4])) {
					return true;
				}

			}
		}

		return found;
	}

	/**
	 * Verifica se o user dado é do type
	 * 
	 * @param user ID do user
	 * @param type Tipo do user
	 * @return true caso verdade ou false caso contrario
	 */
	public static Boolean checkPermissions(String user, String type) {
		Boolean havePermission = false;

		String[] users = getUsersArray(readSintese());
		int len = users.length;
		for (int i = 0; i < len; i++) {
			String[] userArray = users[i].split(";");
			if (userArray[0].equals(user) && userArray[3].equals(type)) {
//				System.out.println(userArray[0] + ":" + userArray[3]);
				havePermission = true;
			}

		}
		return havePermission;
	}

	/**
	 * Cria um novo registo no ficheiro de passwords que corresponde a um user e uma
	 * diretoria identificada pelo o id do user dentro da pasta Servidor
	 * 
	 * @param id   ID do user
	 * @param name Nome do user
	 * @param pass Password do user
	 * @param type Tipo do user
	 * @return true se criado com sucesso false caso contrario
	 */
	public static Boolean createUser(String id, String name, String pass, String type) throws Exception {
		Boolean created = false;

		SecureRandom random = new SecureRandom();
		byte[] saltArray = new byte[8];
		random.nextBytes(saltArray);

		String salt = Base64.getEncoder().encodeToString(saltArray);

		String hashedPassword = encryptPass(pass, saltArray);

		String[] arr = new String[5];
		arr[0] = id;
		arr[1] = name;
		arr[2] = hashedPassword;
		arr[3] = type;
		arr[4] = salt;

		StringBuilder data = new StringBuilder();
		int len = arr.length;
		for (int i = 0; i < len; i++) {
			data.append(arr[i] + ";");
		}
		data.append("\n");
		try {
			updateSintese(data.toString());

			Path path = Paths.get("./Servidor/" + id);
			Files.createDirectory(path);

			created = true;

		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
		return created;
	}

	/**
	 * Listagem de ficheiro da diretoria de um user
	 * 
	 * @param userId Id do user
	 * @return lista de ficheiro ou 'empty' caso vazia
	 */
	public static ArrayList<String> listUserFiles(String userId) {
		ArrayList<String> files = new ArrayList<String>();
		File dir = new File("./Servidor/" + userId);
		File[] directoryListing = dir.listFiles();
		if (directoryListing.length > 0) {
			for (File child : directoryListing) {
				files.add(child.getName());
			}
		} else {
			files.add("empty");
		}

		return files;
	}

	/**
	 * Verifica se um dado ficheiro existe na diretoria de um user
	 * 
	 * @param fileName Nome do ficheiro a encontrar
	 * @param userId   Id do user
	 * @return true se existir ou false caso contrario
	 */
	public static Boolean findFile(String fileName, String userId) {

		for (String file : listUserFiles(userId)) {
			if (file.equals(fileName)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Conta o numero de vezes que um ficheiro aparece repetido na diretoria de user
	 * 
	 * @param fileName Nome do ficheiro a contar
	 * @param userId   Id do user
	 * @return Um int com o numero de ficheiros identicos
	 */
	public static int countFiles(String fileName, String userId) {
		int count = 0;
		String name = fileName.split("\\.")[0];

		ArrayList<String> userFiles = listUserFiles(userId);
		for (String file : userFiles) {
			String fname = file.split("\\.")[0];
			if (fname.equals(name) || fname.split("_")[0].equals(name)) {
				count += 1;
			}
		}
		return count;
	}

	public static ArrayList<String> getUsersList() throws IOException {
		ArrayList<String> usersmu = new ArrayList<String>();
		FileInputStream passwordstream = new FileInputStream("./passwords.txt");
		try (BufferedReader br = new BufferedReader(new InputStreamReader(passwordstream))) {
			String ls;
			while ((ls = br.readLine()) != null) {
				String[] lssplit = ls.split(";");
				usersmu.add(lssplit[0] + " " + lssplit[1]);
			}
		}
		return usersmu;
	}

	public static String[] getUsersArray(String data) {
		String[] users = data.split("\n");

		return users;
	}

	/**
	 * Cria uma diretoria para guardar as diretorias de cada user criado e seus
	 * ficheiros
	 * 
	 * @throws IOException
	 */
	public static void createDir() throws IOException {
		try {
			Path path = Paths.get("./Servidor/");
			boolean dir = Files.isDirectory(path);

			if (!dir) {
				Files.createDirectory(path);
			}
		} catch (IOException e) {
			System.out.println("An error occurred creating the directory.");
			e.printStackTrace();
		}

	}

	public static void genKeyStore(String[] user) {
		String command = "keytool -genkeypair -alias " + user[0]
				+ " -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore." + user[0] + " -dname CN=" + user[1]
				+ " -dname OU=Hospital -dname O=FCUL -dname L=Lisboa -dname ST=LS -dname C=PT" + " -keypass " + user[2];

//		System.out.println(command);
		String[] cmd = command.split(" ");
		try {
			Runtime.getRuntime().exec(cmd);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void hybridCipher(String fileName, String userId) throws Exception {

		// gerar uma chave aleatoria para utilizar com o AES
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128);
		SecretKey key = kg.generateKey();

		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.ENCRYPT_MODE, key);

		FileInputStream fis;
		FileOutputStream fos;
		CipherOutputStream cos;

		fis = new FileInputStream("./Servidor/" + userId + "/" + fileName);
		fos = new FileOutputStream("./Servidor/" + userId + "/" + fileName + ".cif");

		cos = new CipherOutputStream(fos, c);
		byte[] b = new byte[2048]; // arr 2048
		int i = fis.read(b);
		while (i != -1) {
			cos.write(b, 0, i);
			i = fis.read(b);
		}
		cos.close();
		fos.close();
		fis.close();

		// Obter a chave pública da keystore -> certificado

		FileInputStream kFile = new FileInputStream("./keystore.servidor");
		KeyStore kStore = KeyStore.getInstance("PKCS12");
		kStore.load(kFile, "servidor".toCharArray()); // password da keystore
		Certificate cert = kStore.getCertificate("servidor"); // alias do user

		// Cifrar a chave AES com a chave publica da keystore

		Cipher c1 = Cipher.getInstance("RSA");
		c1.init(Cipher.WRAP_MODE, cert);

		byte[] keyEncoded = c1.wrap(key);

		// Guardar no file o resultado da cifra
		FileOutputStream kos = new FileOutputStream("./hybrid.key");
		kos.write(keyEncoded);
		kos.close();

		System.out.println("Ficheiro " + fileName + " cifrado");
		// Apagar ficheiro em formato normal
		File origFile = new File("./Servidor/" + userId + "/" + fileName);
		origFile.delete();

	}

	public static void hybridDecipher(String fileName, String userId) throws Exception {
		FileInputStream kis;
		FileInputStream fis;
		FileOutputStream fos;

		fis = new FileInputStream("./Servidor/" + userId + "/" + fileName + ".cif");
		fos = new FileOutputStream("./Servidor/" + userId + "/" + fileName);

		kis = new FileInputStream("./hybrid.key"); // Ler chave hibrida
		byte[] keyAESCifrada = new byte[kis.available()]; // Tamanho do ficheiro da chave
		kis.read(keyAESCifrada);

		// Obter a chave para decifrar AES -> chave privada do user -> ler da
		// keystore.user
		FileInputStream kFile = new FileInputStream("keystore.servidor");
		KeyStore kStore = KeyStore.getInstance("PKCS12");
		kStore.load(kFile, "servidor".toCharArray()); // password da keystore
		Key privateKey = kStore.getKey("servidor", "servidor".toCharArray());

		// Decifrar a chave AES

		Cipher cRSA = Cipher.getInstance("RSA");
		cRSA.init(Cipher.UNWRAP_MODE, privateKey);
		Key aesKey = cRSA.unwrap(keyAESCifrada, "AES", Cipher.SECRET_KEY);

		// Decifrar o ficheiro com a chave AES decifrada
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.DECRYPT_MODE, aesKey);

		CipherInputStream cis = new CipherInputStream(fis, c);
		int b;
		byte[] d = new byte[2048];
		while ((b = cis.read(d)) != -1) {
			fos.write(d, 0, b);
		}

		fos.flush();
		fos.close();
		fis.close();
		kis.close();

		System.out.println("Ficheiro " + fileName + " decifrado");
	}

	public static String encryptPass(String password, byte[] salt) throws Exception {

		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);

		// Gerar a chave secreta baseando-se na password
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey key = kf.generateSecret(keySpec);

		byte[] hash = key.getEncoded();

		return Base64.getEncoder().encodeToString(hash);
	}

	public static Boolean validateEncryptPass(String givenPass, String hashedPass, String userSalt) throws Exception {

		byte[] salt = Base64.getDecoder().decode(userSalt);

		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);

		// Gerar a chave secreta baseando-se na password
		PBEKeySpec keySpec = new PBEKeySpec(givenPass.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey key = kf.generateSecret(keySpec);

		byte[] hash = key.getEncoded();

		String givenPassHashed = Base64.getEncoder().encodeToString(hash);

		if (hashedPass.equals(givenPassHashed)) {
			return true;
		} else {
			return false;
		}

	}

	public static String digitalSign(String userId, String fileName) throws Exception {
		// Obter a chave privada do servidor
		FileInputStream kFile = new FileInputStream("keystore.servidor");
		KeyStore kStore = KeyStore.getInstance("PKCS12");
		kStore.load(kFile, "servidor".toCharArray()); // password da keystore
		Key privateKey = kStore.getKey("servidor", "servidor".toCharArray());

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign((PrivateKey) privateKey);

		FileInputStream fis;
		FileOutputStream fos;

		fis = new FileInputStream("./Servidor/" + userId + "/" + fileName); // Ficheiro para assinar e cifrar
		fos = new FileOutputStream("./Servidor/" + userId + "/signed.servidor"); // Ficheiro já assinado e cifrado

		byte[] b = new byte[2048];
		int i = fis.read(b);
		while (i != -1) {
			sign.update(b, 0, i);
			i = fis.read(b);
		}

		fos.write(sign.sign());
		fos.close();
		fis.close();

		File signFile = new File("./Servidor/" + userId + "/signed.servidor");
		if (signFile.exists()) {
			return "signed.servidor";
		} else {
			return "";
		}

	}

	public static Boolean verifySign(String userId, String sUserId, ArrayList<String> files) throws Exception {

		String origFile = null;
		String signFile = null;

		for (String file : files) {
			if (file.contains("signed")) {
				signFile = file;
			} else {
				origFile = file;
			}
		}

		// Obter a chave publica do user que assinou
		FileInputStream kFile = new FileInputStream("keystore.servidor"); // store com as chaves publicas
		KeyStore kStore = KeyStore.getInstance("PKCS12");
		kStore.load(kFile, "servidor".toCharArray()); // password da keystore do servidor

		Certificate cert = kStore.getCertificate(userId);

		Signature sign = Signature.getInstance("SHA256withRSA");

		sign.initVerify(cert); // para verificar assinatura

		FileInputStream fis;
		FileInputStream fsig;

		fis = new FileInputStream("./Servidor/" + sUserId + "/" + origFile); // Ficheiro para assinar e cifrar
		fsig = new FileInputStream("./Servidor/" + sUserId + "/" + signFile); // Ficheiro já assinado e cifrado

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
		File dir = new File("./Servidor/" + userId);
		File[] directoryListing = dir.listFiles();
		if (directoryListing.length > 0) {
			for (File child : directoryListing) {

				if (child.getName().contains("signed")) {
					child.delete();
				}

			}
		}

	}

	public static void writeFileMAC(String password) throws Exception {

		FileOutputStream fos = new FileOutputStream("passwords.txt");

		Mac mac = Mac.getInstance("HmacSHA1");

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream kFile = new FileInputStream("keystore.servidor");
		ks.load(kFile, "servidor".toCharArray());
		SecretKey key = (SecretKey) ks.getKey("servidor", "servidor".toCharArray());

		mac.init(key);

		ObjectOutputStream oos = new ObjectOutputStream(fos);
		
		byte buf[] = password.getBytes();
		mac.update(buf);
		oos.writeObject(password);
		oos.writeObject(mac.doFinal());
		fos.close();

		FileInputStream fis = new FileInputStream("passwords.txt");
		byte[] dataBytes = new byte[1024];
		int nread = fis.read(dataBytes);
		while (nread > 0) {
			mac.update(dataBytes, 0, nread);
			nread = fis.read(dataBytes);
		}
		
		byte[] macbytes = mac.doFinal();
	}

}
