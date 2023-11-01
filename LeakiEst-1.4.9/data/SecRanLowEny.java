import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class SecRanLowEny {

	public static void main(String[] args) throws IOException {
		PrintWriter out = new PrintWriter(new FileWriter("java-securerandom-lowentropy.txt"));

		for (int i = 0; i < 500000; i++) {
			SecureRandom genSeed = new SecureRandom();
			long seed = genSeed.nextInt(200);
			byte[] bytes = ByteBuffer.allocate(8).putLong(seed).array();
			SecureRandom gen = new SecureRandom(bytes);
			int first = gen.nextInt(10);
			int second = gen.nextInt(10);
			
			out.println("(" + second + "," + first + ")");
		}
		
		out.close();
	}
	
}
