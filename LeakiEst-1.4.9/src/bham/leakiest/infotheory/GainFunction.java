/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2014 Yusuke Kawamoto
 */
package bham.leakiest.infotheory;

import java.util.*;
import bham.leakiest.*;

/**
 * This class represents a state.
 * 
 * @author Yusuke Kawamoto
 * @version 1.3
 */
public class GainFunction {
    private static int verbose = TestInfoLeak.verbose;
    private int ERROR = 1;
 
	// Parameters for calculiting gains
    private String stringGainFunction = "";
    private int nameGainFunction = 1;
    private int optionNumber = 0;

	// Gain function names
	private final int GAIN_NOT_FOUND = -1;
	private final int GAIN_ID = 1;
	private final int GAIN_DISTANCE = 10;
	private final int GAIN_BIN_GENERAL = 20;
	private final int GAIN_BIN_TWO_BLOCKS = 21;
	private final int GAIN_BIN_HAPPY = 22;
	private final int GAIN_BIN_K_TRIES = 23;
	private final int GAIN_EG_PASSWORD = 30;
	private final int GAIN_EG_LOZERE = 31;
	private final int GAIN_EG_TIGER = 32;

	// Distance types
	private final int DISTANCE_USUAL = 1;
	private final int DISTANCE_LOZERE = 2;
	private final int METRIC_NOT_FOUND = 3;
	
    /**
	 * Constructs a gain function.
	 * @param nameFunction a name of the gain function
	 */
	public GainFunction(String nameFunction) {
		stringGainFunction = nameFunction;
		if(nameFunction.equalsIgnoreCase("id")) {
			nameGainFunction = GAIN_ID;
		} else if(nameFunction.equalsIgnoreCase("distance")) {
			nameGainFunction = GAIN_DISTANCE;
		} else if(nameFunction.equalsIgnoreCase("binary")) {
			nameGainFunction = GAIN_BIN_GENERAL;
		} else if(nameFunction.equalsIgnoreCase("two-blocks")) {
			nameGainFunction = GAIN_BIN_TWO_BLOCKS;
		} else if(nameFunction.equalsIgnoreCase("happy")) {
			nameGainFunction = GAIN_BIN_HAPPY;
		} else if(nameFunction.endsWith("-tries")) {
			try {
				nameGainFunction = GAIN_BIN_K_TRIES;
				String[] strs = nameFunction.split("-tries");
				optionNumber = Integer.parseInt(strs[0]);
				//System.out.println(optionNumber + "-tries");
			} catch(Exception ex) {
				System.out.println("Commandline error: The number of guessing attempts is not specified correctly.");
				System.exit(1);
			}
		} else if(nameFunction.equalsIgnoreCase("eg-password")) {
			nameGainFunction = GAIN_EG_PASSWORD;
		} else if(nameFunction.equalsIgnoreCase("eg-lozere")) {
			nameGainFunction = GAIN_EG_LOZERE;
		} else if(nameFunction.equalsIgnoreCase("eg-tiger")) {
			nameGainFunction = GAIN_EG_TIGER;
		} else {
			nameGainFunction = GAIN_NOT_FOUND;
			System.out.println("Commandline error: The specified gain function is not found in the list: " + nameFunction);
			System.exit(1);
		}
		if(verbose >= 5)
			System.out.println(" A gain function is created.");
	}

	/**
	 * Returns the gain of the attacker when a guess, an input
	 * and a guess domain are given.
	 * 
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
	 * @param guessDomain the guess domain
	 * @param inputDomain the input domain
	 * @return the gain of the attacker
	 */
	public double gain(String[] guess, String input, Set<String> guessDomain, String[] inputDomain) {
		if(guess == null) {
	    	System.out.println("Error in an element of the guess domain.");
			printGainFunctionsList();
			System.exit(1);
		}
		
		switch(nameGainFunction) {
		case(GAIN_ID):
			if(guess.length == 1)
				return identityGainFunction(guess[0], input);
			break;
		case(GAIN_BIN_GENERAL):
			return binGeneralGainFunction(guess, input);
		//case(GAIN_BIN_TWO_BLOCKS):
			//return binTwoBlocksGainFunction(guess, input);
		case(GAIN_BIN_K_TRIES):
			return binKTriesGainFunction(guess, input, optionNumber, inputDomain);
		case(GAIN_DISTANCE):
			if(guess.length == 1)
				return distanceGainFunction(guess[0], input, guessDomain, DISTANCE_USUAL);
			break;
		case(GAIN_BIN_HAPPY):
			if(guess.length == 1)
				return binHappyGainFunction(guess[0], input);
			break;
		//case(GAIN_EG_PASSWORD):
			//return egPasswordGainFunction(guess, input);
		case(GAIN_EG_LOZERE):
			if(guess.length == 1)
				return distanceGainFunction(guess[0], input, guessDomain, DISTANCE_LOZERE);
			break;
		case(GAIN_EG_TIGER):
			if(guess.length == 1)
				return egTigerGainFunction(guess[0], input);
			break;
		case(GAIN_NOT_FOUND):
			printGainFunctionsList();
			System.exit(1);
		default:
			printGainFunctionsList();
			System.exit(1);
		}
		System.out.println("Error in the guess domain file: A guess consists of more than one guesses.");
		printGainFunctionsList();
		return ERROR;
	}

	/**
	 * Returns the name of the gain function.
	 * @return the name of the gain function
	 */
	public String getNameOfGainFunction() {
		return this.stringGainFunction;
	}
	
	/**
	 * Prints the list of all gain functions available in the leakiEst.
	 * 
	 */
	public void printGainFunctionsList() {
		System.out.println("");
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("List of the gain functions available in leakiEst");
		System.out.println("  id                      identity gain function");
		System.out.println("  distance                gain function induced from distance function");
		System.out.println("  binary <block list>     general binary gain function for W := <block list>");
		//System.out.println("  two-blocks <block>      2-block gain function for W = {<block>, X - <block>}");
		System.out.println("  happy                   happy gain function");
		System.out.println("  <number>-tries          <number>-tries gain function");
		System.out.println("                          for W = { w subseteq <domain> | |w| <= <number> }");
		//System.out.println("  eg-password             gain function for the password example in CSF'12");
		System.out.println("  eg-lozere               gain function for the lozere example in CSF'12");
		System.out.println("  eg-tiger                gain function for the tiger example in CSF'12");
	}

	
	/**
	 * Returns whether each guess in a given guess domain is contained
	 * in a given probability distribution.
	 * 
	 * @param pd probability distribution
	 * @param guessDomain guess domain
	 * @return whether each guess in guessDomain is contained in pd
	 */
	public static boolean checkConsistency(ProbDist pd, Set<String> guessDomain) {
		State[] sts = pd.getStatesArray();
		ArrayList<String> allGuesses = new ArrayList<String>();

		// collect guesses from guessDomain (sequences of guesses)
		for(String str : guessDomain) {
			String[] guessArray = str.split(",", 0);
			for(String newGuess : guessArray) {
				if(!allGuesses.contains(newGuess)) {
					allGuesses.add(newGuess);
				}
			}
		}
		
		// check whether each guess in guessDomain is contained in pd 
		for(String guess : allGuesses) {
			boolean consistent = false;
			State tmp = new State();
			for(State st : sts) {
				try {
					if(guess.trim().equalsIgnoreCase(st.getValue("input"))) {
						consistent = true;
						break;
					}
				} catch(Exception ex) {
					System.out.println("Error in the format of the prior or guess domain file.");
					System.exit(1);
				}
				tmp = st;
			}
			if(!consistent) {
				if(verbose >= 5) {
					System.out.println("Caution: The guess is " + guess);
					System.out.println("Caution: The input is " + tmp.getValue("input") + "while the state is ");
					tmp.printState();
				}
				return false;
			}
		}
		return true;
	}

	
	/**
	 * TODO: Complete this
	 * @param pd
	 * @param guessDomain
	 * @return
	 */
	/*
	public String[] setGuessesForKTriesGains(ProbDist pd, Set<String> guessDomain) {
		// enumerate all subsets consisting of distinct guesses
		if(optionNumber > 0 && optionNumber < 64) {
			int size = 1 << pd.numStates();
			
			// enumerate all subsets W of the input domain with |W| <= k 
			String[] guesses = new String[size];
			for(int i = 0; i < size; i++) {
				if(Integer.bitCount(i) <= optionNumber) {
					for()
					String str = sprinf();
					
					guessDomain.add(str);
				}
			}
			
		} else {
			System.out.println("Commandline error: The number of guessing attempts is negative or too large.");
			System.exit(1);
		}

		return guesses;
	}
	 */
	

	/*************************************************************************/
	/**
	 * Returns the gain value of the identity gain function
	 * given a guess and an input.
	 * 	
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
	 * @return whether guess is correct or not
	 */
	public double identityGainFunction(String guess, String input) {
		if(guess.equals(input))
			return 1;
		else
			return 0;
	}


	/*
     * Returns the distance between a guess and an input
     * by a specified metric.
	 * 
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
	 * @param metric type of distances
     * @return the distance between guess and input in Lozere's example
	 */
	private double distance(String guess, String input, int metric) {
		double res = 0;
		switch(metric) {
		case(DISTANCE_USUAL):
			res = distance(guess, input);
		case(DISTANCE_LOZERE):
			res = distanceLozere(guess, input);
		case(METRIC_NOT_FOUND):
			printGainFunctionsList();
			System.exit(1);
		default:
			printGainFunctionsList();
			System.exit(1);
		}
		return res;
	}
	
	
    /*
     * Returns the (usual) distance between a guess and an input.
     * 	
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
     * @return the (usual) distance between guess and input
     */
	private double distance(String guess, String input) {
		double w = 0;
		double x = 0;
		try {
			w = Double.parseDouble(guess);
			x = Double.parseDouble(input);
		} catch(Exception ex) {
			System.out.println("Commandline error: A guess or an input is not a number.");
			System.exit(1);
		}
		return Math.abs(x - w);
	}
	
	/*
     * Returns the distance between a guess and an input
     * in Lozere's example in CSF'12.
	 * 
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
     * @return the distance between guess and input in Lozere's example
	 */
	private double distanceLozere(String guess, String input) {
		double w = 0;
		double x = 0;
		try {
			w = Double.parseDouble(guess);
			x = Double.parseDouble(input);
		} catch(Exception ex) {
			System.out.println("Commandline error: A guess or an input is not a number.");
			System.exit(1);
		}
		if(x - 60 < w && w <= x)
			return (x - w) / 60;
		else
			return 1;
	}
	
	/**
	 * Returns the gain value of the distance gain function
	 * given a guess and an input.
	 * 
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
	 * @param guessDomain the set of all guesses
	 * @param metric type of distances
	 * @return the gain value of the distance gain function
	 *         given guess and input
	 */
	public double distanceGainFunction(String guess, String input, Set<String> guessDomain, int metric) {
		double maxDistance = 0;
		for(String w : guessDomain) {
			maxDistance = Math.max(maxDistance, distance(w, input, metric));
		}
		double normDistance = distance(guess, input, metric) / maxDistance; 
		return 1 - normDistance;
	}

	/**
	 * Returns the gain value of the general binary gain function
	 * given a guess and an input.
	 * 
	 * @param guesses attaker's guesses on the securet input
	 * @param input secret input
	 * @return the gain value of the genral binary gain function
	 *         given guess and input
	 */
	public double binGeneralGainFunction(String[] guesses, String input) {
		for(String w : guesses) {
			if(w == input) {
				return 1;
			}
		}
		return 0;
	}

	/**
	 * Returns the gain value of the 2-blocks gain function
	 * given a guess and an input.
	 * 
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
	 * @return the gain value of the 2-blocks gain function
	 *         given guess and input
	 */
	/*
	public double binTwoBlocksGainFunction(String[] guess, String input) {
		
	}
	*/

	/**
	 * Returns the gain value of the happy gain function
	 * given a guess and an input.
	 * 
	 * @param guess attaker's guess on the securet input
	 * @param input secret input
	 * @return the gain value of the happy gain function
	 *         given guess and input
	 */
	public double binHappyGainFunction(String guess, String input) {
		return 1;
	}

	//TODO: Modify this using inputDomain instead of guesses.
	/**
	 * Returns the gain value of the k-tries gain function
	 * given a guess and an input.
	 * 
	 * @param guesses attaker's guess on the securet input
	 * @param input secret input
	 * @param numOfTries the number of tries of guessing
	 * @param inputDomain the set of all inputs
	 * @return the gain value of the k-tries gain function
	 *         given guess and input
	 */
	public double binKTriesGainFunction(String[] guesses, String input, int numOfTries, String[] inputDomain) {
		if(guesses.length != numOfTries) {
			System.out.println("Error: The number of tries is incorrectly specified.");
			System.out.println("  guesses.length: " + guesses.length);
			System.out.println("  numOfTries:     " + numOfTries);
			System.exit(1);
		}

		/*
		System.out.println("input: " + input);
		System.out.print("  guess: ( ");
		for(String w: guesses) {
			System.out.print(w + " ");
		}
		System.out.println(")");
		*/
		
		for(String w: guesses) {
			if(w.equals(input)) {
				//System.out.println("  gain = 1");
				return 1;
			}
		}
		//System.out.println("  gain = 0");
		return 0;
	}

	/*
	 *  TODO: Complete this.
	public double egPasswordGainFunction(String[] guess, String input) {
		
	}
	*/

	public double egTigerGainFunction(String guess, String input) {
		if(guess.equals(input))
			return 1;
		else if(guess.equals(""))
			return 0.5;
		else
			return 0;
	}
}
