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

import java.util.Set;
import bham.leakiest.*;

/**
 * This is a library for calculating g-entropy, conditional g-entropy
 * and g-leakage, defined by Alvim et. al in "Measuring Information 
 * Leakage using Generalized Gain Functions". <br>
 *
 * Probability Mass Functions are represented by an array of doubles
 * p(element i) = pmf[i] or by ProbDist class. <br>
 *
 * @author Yusuke Kawamoto
 * @version 1.3
 */
public class GLeakage {
	// Verbose
	private static int verbose = TestInfoLeak.verbose;

	/**
	 * Base when computing the logarithms.
	 */
	public static final int base_log = 2;
	private static final int ERROR = -1;
	

	/*************************************************************************/
	/**
	 * Calculates the g-entropy of a probability distribution.
	 * <BR>
	 * H_g(pmf) = -log( max_w sum_i (pmf[i] g(w, i)) )
	 * 
	 * @param pmf pmf array
	 * @param sts states array
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @param inputDomain the set of all inputs
	 * @return The g-entropy of pd
	 */
	public static double gEntropy(double[] pmf, State[] sts, GainFunction gf, Set<String> guessDomain, String[] inputDomain) {
		// TODO: Verify this method!!
		// Taking a maximum over all guesses w in guessDomain
		double maxProb = 0;
		try {
			for(String guess : guessDomain) {
				//System.out.println("  guess: " + guess);
				try{
					// convert a sequence of guesses into an array of guesses
					String[] guessArray = guess.split(",", 0);

					// Summing probabilities p(x) multiplied by gains g(w, x)
					double sum = 0;
					for(int ix = 0; ix < sts.length; ix++) {
						String input = sts[ix].getValue("input");
						sum += pmf[ix] * gf.gain(guessArray, input, guessDomain, inputDomain);
						//System.out.print("    pmf[ix] = " + pmf[ix] + "  gain = " + gf.gain(guessArray, sts[ix].getValue("input"), guessDomain));
						//System.out.println("  sum = " + sum);
					}
					maxProb = Math.max(maxProb, sum);
				} catch(Exception ex0) {
			    	System.out.println("Error in parsing an element of the guess domain: " + ex0);
			    	System.out.println("  The file does not follow a guess domain file (-guess) format.");
					System.exit(1);
				}
			}
		} catch(Exception ex) {
	    	System.out.println("Error in the prior or guess domain file.");
			return ERROR;
		}
		return - InfoTheory.log(Math.min(maxProb, 1), base_log);
	}

	/**
	 * Calculates the g-entropy of a probability distribution.
	 * 
	 * @param pd probability distribution
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @return The g-entropy of pd
	 */
	public static double gEntropy(ProbDist pd, GainFunction gf, Set<String> guessDomain) {
		double[] pmf = pd.getPMFArray();
		State[] sts = pd.getStatesArray();
		/*
		if(pmf == null || guessDomain == null || guessDomain.size() > pmf.length) {
	    	System.out.println("Error in the guess domain file: The size of the guess domain is incorrect.");
	    	System.out.println("  The size of the prior =        " + pmf.length);
	    	System.out.println("  The size of the guess domain = " + guessDomain.size());
			return ERROR;
		}
		*/
		// the input domain
		String[] inputDomain = new String[pmf.length];
		for(int ix = 0; ix < inputDomain.length ; ix++) {
			inputDomain[ix] = sts[ix].getValue("input");
		}
		return gEntropy(pmf, sts, gf, guessDomain, inputDomain);
	}

	/**
	 * Calculates the posterior g-entropy of a channel
	 * given a probability distribution, a gain function gf,
	 * and the set of all guesses guessDomain.
	 * 
	 * @param pmf pmf array
	 * @param sts states array
	 * @param channel channel
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @param inputDomain the set of all inputs
	 * @return The posterior g-entropy of channel given pmf, sts, 
	 *         channel, gf and guessDomain
	 */
	public static double conditionalGEntropy(double[] pmf, State[] sts, Channel channel, GainFunction gf, Set<String> guessDomain, String[] inputDomain) {
		// TODO: Verify this method!!
		double[][] matrix = channel.getMatrix();

		// Summing over all outputs y in outputNames
		double res = 0;
		try {
			for(int iy = 0; iy < channel.getOutputNames().length; iy++) {
				// Taking a maximum over all guesses w in guessDomain
				double maxProb = 0;
				for(String guess : guessDomain) {
					try {
						// convert a sequence of guesses into an array of guesses
						String[] guessArray = guess.split(",", 0);

						// Summing probabilities p(x) multiplied by conditional probabilities C[x, y] gains g(w, x)
						double sum = 0;
						for(int ix = 0; ix < sts.length; ix++) {
							String input = sts[ix].getValue("input");
							sum += pmf[ix] * matrix[ix][iy] * gf.gain(guessArray, input, guessDomain, inputDomain);
						}
						maxProb = Math.max(maxProb, sum);
					} catch(Exception ex0) {
				    	System.out.println("Error in parsing an element of the guess domain: " + ex0);
				    	System.out.println("  The file does not follow a guess domain file (-guess) format.");
						System.exit(1);
					}
				}
				res += maxProb;
			}
		} catch(Exception ex) {
	    	System.out.println("Error in the prior or guess domain file.");
			return ERROR;
		}
		return - InfoTheory.log(Math.min(res, 1), base_log);
	}

	/**
	 * Calculates the posterior g-entropy of a channel
	 * given a probability distribution, a gain function gf,
	 * and the set of all guesses guessDomain.
	 * 
	 * @param pd prbability distribution
	 * @param channel channel
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @return The posterior g-entropy of channel given pd, channel,
	 *         gf and guessDomain
	 */
	public static double conditionalGEntropy(ProbDist pd, Channel channel, GainFunction gf, Set<String> guessDomain) {
		// TODO: Verify this method!!
		String[] inputDomain = channel.getInputNames();
		double[] pmf = pd.probDistToPMFArray(inputDomain);
		State[] sts = pd.probDistToStatesArray(inputDomain);
		/*
		if(pmf == null || guessDomain == null || guessDomain.size() > pmf.length) {
	    	System.out.println("Error in the guess domain file: The size of the guess domain is incorrect.");
	    	System.out.println("  The size of the prior =        " + pmf.length);
	    	System.out.println("  The size of the guess domain = " + guessDomain.size());
			return ERROR;
		}
		*/
		return conditionalGEntropy(pmf, sts, channel, gf, guessDomain, inputDomain);
	}

	/**
	 * Calculates the g-leakage from a channel
	 * given an input probability distribution pd
	 * given a probability distribution, a gain function gf,
	 * and the set of all guesses guessDomain.
	 * 
	 * @param pd prbability distribution
	 * @param channel channel
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @return The g-leakage of channel given pd, 
	 *         gf and guessDomain
	 */
	public static double gLeakage(ProbDist pd, Channel channel, GainFunction gf, Set<String> guessDomain) {
		String[] inputDomain = channel.getInputNames();
		double[] pmf = pd.probDistToPMFArray(inputDomain);
		State[] sts = pd.probDistToStatesArray(inputDomain);

		/*
		String stringGainFunction = gf.getNameOfGainFunction();
		if(stringGainFunction.endsWith("-tries")) {
			gf.setGuessesForKTriesGains(pd, guessDomain);
		}
		*/
		/*
		if(pmf == null || guessDomain == null || guessDomain.size() > pmf.length) {
	    	System.out.println("Error in the guess domain file: The size of the guess domain is incorrect.");
	    	System.out.println("  The size of the prior =        " + pmf.length);
	    	//System.out.println("  prior =        " + pmf[0] + "  " + pmf[1] + "  ");
	    	System.out.println("  The size of the guess domain = " + guessDomain.size());
			return ERROR;
		}
		*/

		// Calculate (prior) g-entropy
		double gPrior = gEntropy(pmf, sts, gf, guessDomain, inputDomain);

		// Calculate posterior g-entropy
		double gPosterior = conditionalGEntropy(pmf, sts, channel, gf, guessDomain, inputDomain);

		// Calculate g-leakage (= prior g-entropy - posterior g-entropy) 
		if(gPrior != ERROR && gPosterior != ERROR)
			return gPrior - gPosterior;
		else
			return (double)ERROR;
	}
	
}
