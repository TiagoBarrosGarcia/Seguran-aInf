package server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;

//Threads utilizadas para comunicacao com os clientes
public class ServerThread extends Thread {
	private Socket socket = null;

	private static ObjectOutputStream outStream = null;
	private static ObjectInputStream inStream = null;
	private static BufferedInputStream buffInStream = null;
	private static BufferedOutputStream buffOutStream = null;

	ServerThread(Socket inSoc) {
		this.socket = inSoc;
		System.out.println("Thread is runinng");
	}

	public void run() {
		try {
			ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

			String operation = (String) inStream.readObject();

			// -c
			if (operation.equals("-c")) {
				String type = "admin";
				String userId = (String) inStream.readObject();
				String password = (String) inStream.readObject();
				String newUserId = (String) inStream.readObject();
				String newUserName = (String) inStream.readObject();
				String newUserPass = (String) inStream.readObject();
				String newUserType = (String) inStream.readObject();

				if (myDoctorServer.findUser(userId, password)) {
					if (myDoctorServer.checkPermissions(userId, type)) {
						Boolean created = myDoctorServer.createUser(newUserId, newUserName, newUserPass, newUserType);
						outStream.writeObject(created);

					} else {
						outStream.writeObject(false);
						outStream.writeObject("Don't have permissions to execute this command!");
					}

				} else {
					outStream.writeObject(false);
					outStream.writeObject("User not found!");
				}

				// -mu
			} else if (operation.equals("-mu")) {
				String type = "medico";
				String type2 = "tecnico";
				String userId = (String) inStream.readObject();
				String password = (String) inStream.readObject();

				if (myDoctorServer.findUser(userId, password)) {
					if (myDoctorServer.checkPermissions(userId, type)
							|| myDoctorServer.checkPermissions(userId, type2)) {

						ArrayList<String> users = myDoctorServer.getUsersList();
						outStream.writeObject(true);
						outStream.writeObject(users);

					} else {
						outStream.writeObject(false);
						outStream.writeObject("Don't have permissions to execute this command!");
					}

				} else {
					outStream.writeObject(false);
					outStream.writeObject("User not found!");
				}

				// -md
			} else if (operation.equals("-md")) {
				String type = "utente";
				String userId = (String) inStream.readObject();
				String password = (String) inStream.readObject();

				if (myDoctorServer.findUser(userId, password)) {
					if (myDoctorServer.checkPermissions(userId, type)) {

						ArrayList<String> files = myDoctorServer.listUserFiles(userId);
						if (files.get(0).equals("empty")) {
							outStream.writeObject(false);
							outStream.writeObject("Directory is empty!");
						} else {
							outStream.writeObject(true);
							outStream.writeObject(files);
						}

					} else {
						outStream.writeObject(false);
						outStream.writeObject("Don't have permissions to execute this command!");
					}

				} else {
					outStream.writeObject(false);
					outStream.writeObject("User not found!");
				}

				// -mx
			} else if (operation.equals("-mx")) {
				String type = "medico";
				String userId = (String) inStream.readObject();
				String password = (String) inStream.readObject();
				String sUserId = (String) inStream.readObject();

				if (myDoctorServer.findUser(userId, password)) {
					if (myDoctorServer.checkPermissions(userId, type)) {

						ArrayList<String> files = myDoctorServer.listUserFiles(sUserId);
						if (files.get(0).equals("empty")) {
							outStream.writeObject(false);
							outStream.writeObject("Directory is empty!");
						} else {
							outStream.writeObject(true);
							outStream.writeObject(files);
						}

					} else {
						outStream.writeObject(false);
						outStream.writeObject("Don't have permissions to execute this command!");
					}

				} else {
					outStream.writeObject(false);
					outStream.writeObject("User not found!");
				}
				// -d
			} else if (operation.equals("-d")) {
				String type = "utente";
				String userId = (String) inStream.readObject();
				String password = (String) inStream.readObject();
				String fileName = (String) inStream.readObject();

				// Decifra o ficheiro pedido
				myDoctorServer.hybridDecipher(fileName, userId);

				if (myDoctorServer.findUser(userId, password)) {
					if (myDoctorServer.checkPermissions(userId, type)) {

						// Decifra o ficheiro pedido
						myDoctorServer.hybridDecipher(fileName, userId);

						// Assina ficheiro
						myDoctorServer.digitalSign(userId, fileName);

						if (myDoctorServer.findFile(fileName, userId)) {

							outStream.writeObject(true);

							ArrayList<String> files = myDoctorServer.listUserFiles(userId);

							outStream.writeObject(files);

							for (String file : files) {
								// Filtrar apenas ficheiros que se quer
								if (file.equals(fileName) || file.contains("signed")) {
									File currentFile = new File("./Servidor/" + userId + "/" + file);

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
							// Apagar ficheiro em formato normal
							File origFile = new File("./Servidor/" + userId + "/" + fileName);
							origFile.delete();
							myDoctorServer.deleteSigned(userId);

						} else {
							outStream.writeObject(false);
							outStream.writeObject("File doesn't exist!");
						}

					} else {
						outStream.writeObject(false);
						outStream.writeObject("Don't have permissions to execute this command!");
					}

				} else {
					outStream.writeObject(false);
					outStream.writeObject("User not found!");
				}
				// -du
			} else if (operation.equals("-du")) {
				String type = "medico";
				String userId = (String) inStream.readObject();
				String password = (String) inStream.readObject();
				String sUserId = (String) inStream.readObject();
				String fileName = (String) inStream.readObject();

				if (myDoctorServer.findUser(userId, password)) {
					if (myDoctorServer.checkPermissions(userId, type)) {

						// Decifra o ficheiro pedido
						myDoctorServer.hybridDecipher(fileName, sUserId);

						// Assina ficheiro
						myDoctorServer.digitalSign(sUserId, fileName);

						if (myDoctorServer.findFile(fileName, sUserId)) {

							outStream.writeObject(true);

							ArrayList<String> files = myDoctorServer.listUserFiles(sUserId);

							outStream.writeObject(files);

							for (String file : files) {
								// Primeiro ficheiro original
								// Filtrar apenas ficheiros que se quer
								if (file.equals(fileName) || file.contains("signed")) {

									File currentFile = new File("./Servidor/" + sUserId + "/" + file);

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
							// Apagar ficheiro em formato normal
							File origFile = new File("./Servidor/" + sUserId + "/" + fileName);
							origFile.delete();
							// Apapa ficheiro de assinatura
							myDoctorServer.deleteSigned(sUserId);

						} else {
							outStream.writeObject(false);
							outStream.writeObject("File doesn't exist!");
						}

					} else {
						outStream.writeObject(false);
						outStream.writeObject("Don't have permissions to execute this command!");
					}

				} else {
					outStream.writeObject(false);
					outStream.writeObject("User not found!");
				}

				// -su
			} else if (operation.equals("-su")) {
				String type1 = "medico";
				String type2 = "tecnico";
				String userId = (String) inStream.readObject();
				String password = (String) inStream.readObject();
				String sUserId = (String) inStream.readObject();
				String fileName = (String) inStream.readObject();
				ArrayList<String> files = (ArrayList<String>) inStream.readObject();

				if (myDoctorServer.findUser(userId, password)) {
					if (myDoctorServer.checkPermissions(userId, type1)
							|| myDoctorServer.checkPermissions(userId, type2)) {

						for (String file : files) {
							if (myDoctorServer.findFile(file, sUserId)) {

								int count = myDoctorServer.countFiles(file, sUserId);

								String fName = file.split("\\.")[0];
								String ext = file.split("\\.")[1];

								String newFileName = fName + "_" + String.valueOf(count) + "." + ext;

								String newFile = "./Servidor/" + sUserId + "/" + newFileName;

								buffOutStream = new BufferedOutputStream(new FileOutputStream(newFile));

								Long size = (Long) inStream.readObject();

								byte[] buffer = new byte[size.intValue()];

								int x = 0;
								int temp = size.intValue();

								while (temp > 0) {
									x = inStream.read(buffer, 0, temp > 1024 ? 1024 : temp);
									buffOutStream.write(buffer, 0, x);
									temp -= x;
								}
								buffOutStream.close();
								outStream.writeObject(true);

							} else {

								String newFile = "./Servidor/" + sUserId + "/" + file;

								buffOutStream = new BufferedOutputStream(new FileOutputStream(newFile));

								Long size = (Long) inStream.readObject();

								byte[] buffer = new byte[1024];

								int x = 0;
								int temp = size.intValue();

								while (temp > 0) {
									x = inStream.read(buffer, 0, temp > 1024 ? 1024 : temp);
									buffOutStream.write(buffer, 0, x);
									temp -= x;
								}
								buffOutStream.close();
								outStream.writeObject(true);

							}

						}

						if (myDoctorServer.verifySign(userId, sUserId, files)) {
							System.out.println("Ficheiro " + fileName + " válido!");
							// Apagar ficheiro com assinatura
							myDoctorServer.deleteSigned(sUserId);
							myDoctorServer.hybridCipher(fileName, sUserId);
						} else {
							System.out.println("Ficheiro " + fileName + " não válido!");
						}

					} else {
						outStream.writeObject(false);
						outStream.writeObject("Don't have permissions to execute this command!");
					}

				} else {
					outStream.writeObject(false);
					outStream.writeObject("User not found!");
				}

			}

			outStream.close();
			inStream.close();

			this.socket.close();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}