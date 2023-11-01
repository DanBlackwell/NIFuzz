import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import java.util.Random;

public class RandomLowEny {

	public static void main(String[] args) throws IOException {
		PrintWriter out = new PrintWriter(new FileWriter("java-random-lowentropy.txt"));

		for (int i = 0; i < 500000; i++) {
			Random genSeed = new Random();
			Random gen = new Random(genSeed.nextInt(200));
			int first = gen.nextInt(10);
			int second = gen.nextInt(10);
			
			out.println("(" + second + "," + first + ")");
		}
		
		out.close();
	}
	
}
