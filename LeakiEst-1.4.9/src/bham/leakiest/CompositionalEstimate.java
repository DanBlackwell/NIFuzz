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
package bham.leakiest;

import java.util.ArrayList;
import java.util.Set;

import bham.leakiest.infotheory.*;

/**
 * This is a library of useful compositional reasoning about estimation
 * of information leakage measures. <br>
 * The theories used in the class appears in a paper iin QEST 2014 <br>
 *
 * @author Yusuke Kawamoto
 * @version 1.3
 */
public class CompositionalEstimate {
	// Task types
	private static final int CLC_MUTUAL_INFO = TestInfoLeak.CLC_MUTUAL_INFO;
	private static final int CLC_CAPACITY = TestInfoLeak.CLC_CAPACITY;
	private static final int CLC_MIN_ENTROPY = TestInfoLeak.CLC_MIN_ENTROPY;
	private static final int CLC_MIN_CAPACITY = TestInfoLeak.CLC_MIN_CAPACITY;
	private static final int CLC_G_LEAK = TestInfoLeak.CLC_G_LEAK;

	// other constant
	private static final double ERROR = TestInfoLeak.ERROR;
	private static final double UNKNOWN = TestInfoLeak.UNKNOWN;
	private static final double APPROX_OPTIMIZED = TestInfoLeak.APPROX_OPTIMIZED;

	// import veriables
	private static final boolean readFromPriorFile = TestInfoLeak.readFromPriorFile;
	private static int verbose = TestInfoLeak.verbose;
	private static boolean PRINT_CHANNELMATRIX = TestInfoLeak.PRINT_CHANNELMATRIX;
	private static boolean PRINT_JOINTMATRIX = TestInfoLeak.PRINT_JOINTMATRIX;
	private static boolean correctLeak = TestInfoLeak.correctLeak;
	private static boolean correctLeakNew = TestInfoLeak.correctLeakNew;
	private static boolean checkJointlySupported = TestInfoLeak.checkJointlySupported;

	/*
	private static ArrayList<Double> leakage = TestInfoLeak.leakage;
	private static ArrayList<Double> zeroLimit = TestInfoLeak.zeroLimit;
	private static ArrayList<Double> lowerLimit = TestInfoLeak.lowerLimit;
	private static ArrayList<Double> upperLimit = TestInfoLeak.upperLimit;
	private static ArrayList<String> name = TestInfoLeak.name;
	private static ArrayList<String> confidence = TestInfoLeak.confidence;
    */
	
	private static ArrayList<Double> leakage = new ArrayList<Double>();
	private static ArrayList<Double> zeroLimit = new ArrayList<Double>();
	private static ArrayList<Double> lowerLimit = new ArrayList<Double>();
	private static ArrayList<Double> upperLimit = new ArrayList<Double>();
	private static ArrayList<String> confidence = new ArrayList<String>();

	/////////////////////////////////////////////////////
	////// Min-entropy leakage estimation functions /////
	/**
	 * Returns H^min(pd) = - log min { pd[x] | x in support(pd) }.
	 * 
	 * @param pd input probability distribution
	 * @return H^min(pd)
	 */
	public static double HMinInf(ProbDist pd) {
		double[] pmf = pd.getPMFArray();
		double minimum = 1.0;
		for(double prob : pmf) {
			if(prob != 0)
				minimum = Math.min(minimum, prob);
		}
		//System.out.println("  minimum = " + minimum);
		//pd.printProbDist();
		return - InfoTheory.log2(minimum);
	}


	/**
	 * Returns MInf defined in our compositionality paper.
	 * 
	 * @param jpd joint input probability distribution
	 * @param numChannels the number of channel compositions
	 * @return MInf
	 */
	public static double[] MInf(ProbDist jpd, int numChannels) {
		// Calculate all marginal distributions of jpd
		ProbDist[] marginals = jpd.getAllMarginals();
		
		double minimum = 1.0;
		double maximum = 1.0;
		for(State jst : jpd.getStatesArray()) {
			double jprob = jpd.getProb(jst);
			if(jprob != 0) {
				double product = 1.0;
				for(int i = 0; i < numChannels; i++) {
					String str = jpd.getProjectedState(jst, i);
					product *= marginals[i].getProb(str);
					//System.out.println("  product[" + i + "] = " + product);
				}
				double frac = product / jprob;
				//System.out.println("  frac = product/jprob = " + product + "/" + jprob + " = " + frac);
				minimum = Math.min(minimum, frac);
				maximum = Math.max(maximum, frac);
			}
		}
		//System.out.println("  minimum = " + minimum);
		//System.out.println("  maximum = " + maximum);
		double[] result = {Math.max(0.0, minimum), Math.max(0.0, maximum)};
		return result;
	}


	// Index for composed inputs
	private static int[] composedInputIndex;
	
	// Index for composed outputs
	private static int[] composedOutputIndex;
	
	// Initialize composedInputIndex and composedOutputIndex
	private static void initializeIndex(int size) {
		composedInputIndex = new int[size];
		composedOutputIndex = new int[size];
		for(int i = 0; i < composedInputIndex.length; i++) {
			composedInputIndex[i] = 0;
		}
		for(int i = 0; i < composedOutputIndex.length; i++) {
			composedOutputIndex[i] = 0;
		}
	}

	// Increment composedInputIndex
	private static void incrementComposedInputIndex(Channel[] channels) {
		for(int i = composedInputIndex.length -1; i >= 0; i--) {
			//System.out.println("    composedInputIndex[" + i + "] = " + composedInputIndex[i]);
			if(composedInputIndex[i] >= channels[i].noOfInputs() - 1) {
				composedInputIndex[i] = 0;
			} else {
				composedInputIndex[i]++;
				break;
			}
		}
	}

	// Increment composedOutputIndex
	private static void incrementComposedOutputIndex(Channel[] channels) {
		for(int i = composedOutputIndex.length -1; i >= 0; i--) {
			//System.out.println("    composedOutputIndex[" + i + "] = " + composedOutputIndex[i]);
			if(composedOutputIndex[i] >= channels[i].noOfOutputs() - 1) {
				composedOutputIndex[i] = 0;
			} else {
				composedOutputIndex[i]++;
				break;
			}
		}
	}

	
	///////////////////////////////////////////
	////// g-leakage estimation functions /////
	/**
	 * Returns Hg^min(pd) = - log min { pd[x] g(w, x) | x in X, w in W, pd[x] g(w, x) != 0 }.
	 * 
	 * @param pd input probability distribution
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @return Hg^min(pd)
	 */
	public static double HgMin(ProbDist pd, GainFunction gf, Set<String> guessDomain) {
		double[] pmf = pd.getPMFArray();
		State[] sts = pd.getStatesArray();

		// the input domain
		String[] inputDomain = new String[pmf.length];
		for(int ix = 0; ix < inputDomain.length ; ix++) {
			inputDomain[ix] = sts[ix].getValue("input");
		}
		
		double minimum = 1.0;
		for(String guess: guessDomain) {
			//System.out.println("  guess: " + guess);
			try{
				// convert a sequence of guesses into an array of guesses
				String[] guessArray = guess.split(",", 0);

				// Taking the non-zero minimum of probabilities p(x) multiplied by gains g(w, x)
				for(int ix = 0; ix < sts.length; ix++) {
					String input = sts[ix].getValue("input");
					double product = pmf[ix] * gf.gain(guessArray, input, guessDomain, inputDomain);
					if(product != 0) {
						minimum = Math.min(minimum, product);
					}
					//System.out.print("    pmf[ix] = " + pmf[ix] + "  gain = " + gf.gain(guessArray, sts[ix].getValue("input"), guessDomain));
					//System.out.println("  min = " + min);
				}
			} catch(Exception ex0) {
		    	System.out.println("Error in parsing an element of the guess domain: " + ex0);
		    	System.out.println("  The file does not follow a guess domain file (-guess) format.");
				System.exit(1);
			}
		}
		//System.out.println("  minimum = " + minimum);
		//pd.printProbDist();
		return - InfoTheory.log2(minimum);
	}
	
	/**
	 * 
	 * @param jpd joint input probability distribution
	 * @param channels array of channels
	 * @return the exact value of the min-entropy leakage of 
	 *         the channel composed in parallel
	 */
	public static double exactParallelMinEntropyLeak(ProbDist jpd, Channel[] channels) {
		// size of the composed channel matrix
		int numRowsComposedMatrix = 1;
		int numColsComposedMatrix = 1;
		for(int num = 0; num < channels.length; num++) {
			numRowsComposedMatrix *= channels[num].noOfInputs();
			numColsComposedMatrix *= channels[num].noOfOutputs();
		}
		
		// Calculate the input names of the composed channel
		String[] composedInputNames = new String[numRowsComposedMatrix];
		for(int i = 0; i < channels[0].noOfInputs(); i++) {
			composedInputNames[i] = channels[0].getInputNames()[i];
		}
		int tmpNumRows = 1;
		for(int num = 0; num < channels.length-1; num++) {
			tmpNumRows *= channels[num].noOfInputs();
	    	//System.out.println("  channels[num+0].noOfInputs() = " + channels[num].noOfInputs());
	    	//System.out.println("  tmpNumRows = " + tmpNumRows);
	    	//System.out.println("  channels[num+1].noOfInputs() = " + channels[num+1].noOfInputs());
	    	//System.out.println("  numRows   = " + numRows);
			composedInputNames = Channel.parallelComposition(composedInputNames, channels[num].getInputNames(), tmpNumRows, channels[num+1].noOfInputs(), numRowsComposedMatrix);
		}
		for(int i = 0; i < composedInputNames.length; i++) {
			composedInputNames[i] = "(" + composedInputNames[i] + ")";
		}

		// input probability distribution array
		double[] pmf = jpd.probDistToPMFArray(composedInputNames);
		
		// initialize composedInputIndex and composedOutputIndex
		initializeIndex(channels.length);

		// initialize maxJointCol
		double[] maxJointCol = new double[numColsComposedMatrix];
		for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
			maxJointCol[colComposed] = 0;
		}

		//System.out.println("  numColsComposedMatrix = " + numColsComposedMatrix);
		//System.out.println("  pmf.length = " + pmf.length);
		for(int rowComposed = 0; rowComposed < pmf.length; rowComposed++) {
			for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
				double condProb = 1;
				for(int num = 0; num < channels.length; num++) {
					int row = composedInputIndex[num];
					int col = composedOutputIndex[num];
					//System.out.print("  rowComposed = " + rowComposed);
					//System.out.print("  colComposed = " + colComposed);
					//System.out.print("  row = " + row);
					//System.out.print("  col = " + col);
					//System.out.print("  num = " + num);
					condProb *= channels[num].getMatrix()[row][col];
					//System.out.print("  cp = " + condProb + " ||");
				}
				double jointProb = pmf[rowComposed] * condProb;
				//System.out.print("  joint = " + jointProb);
				maxJointCol[colComposed] = Math.max(maxJointCol[colComposed], jointProb);
				//System.out.println("  maxJointCol = " + maxJointCol[colComposed]);
				incrementComposedOutputIndex(channels);
			}
			incrementComposedInputIndex(channels);
		}

		// Calculate the conditional min-entropy
		double conditionalMinEntropy = 0;
		for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
			conditionalMinEntropy += maxJointCol[colComposed];
			//System.out.println("  conditional = " + conditionalMinEntropy);
		}
		conditionalMinEntropy = -InfoTheory.log2(conditionalMinEntropy);

		double result = MinEntropy.minEntropy(pmf) - conditionalMinEntropy;
		return result;
	}

	
	/**
	 * 
	 * @param jpd joint input probability distribution
	 * @param channels array of channels
	 * @return the exact value of the min-entropy leakage of 
	 *         the channel composed in parallel in the case 
	 *         input values are shared among channels
	 */
	public static double exactParallelMinEntropyLeakWithSharedInput(ProbDist jpd, Channel[] channels) {
		// size of the composed channel matrix
		//int numRowsComposedMatrix = 1;
		int numColsComposedMatrix = 1;
		for(int num = 0; num < channels.length; num++) {
			//numRowsComposedMatrix *= channels[num].noOfInputs();
			numColsComposedMatrix *= channels[num].noOfOutputs();
		}
		
		// input probability distribution array
		double[] pmf = jpd.probDistToPMFArray(channels[0].getInputNames());

		// initialize composedOutputIndex
		initializeIndex(channels.length);

		// initialize maxJointCol
		double[] maxJointCol = new double[numColsComposedMatrix];
		for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
			maxJointCol[colComposed] = 0;
		}

		//System.out.println("  numColsComposedMatrix = " + numColsComposedMatrix);
		//System.out.println("  pmf.length = " + pmf.length);
		for(int row = 0; row < pmf.length; row++) {
			for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
				double condProb = 1;
				for(int num = 0; num < channels.length; num++) {
					int col = composedOutputIndex[num];
					//System.out.print("  row = " + row);
					//System.out.print("  colComposed = " + colComposed);
					//System.out.print("  col = " + col);
					//System.out.print("  num = " + num);
					condProb *= channels[num].getMatrix()[row][col];
				}
				double jointProb = pmf[row] * condProb;
				//System.out.println("  joint = " + jointProb);
				maxJointCol[colComposed] = Math.max(maxJointCol[colComposed], jointProb);
				incrementComposedOutputIndex(channels);
			}
		}

		// Calculate the conditional min-entropy
		double conditionalMinEntropy = 0;
		for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
			conditionalMinEntropy += maxJointCol[colComposed];
		}
		conditionalMinEntropy = -InfoTheory.log2(conditionalMinEntropy);

		double result = MinEntropy.minEntropy(pmf) - conditionalMinEntropy;
		return result;
	}
	

	/**
	 * Returns a lower and an upper bound on the min-entropy leakage of 
	 * the channel composed in parallel where inputs to different channels 
	 * are drawn independently.
	 * 
	 * @param jpd joint input probability distribution
	 * @param apd approximate joint input probability distribution
	 * @param channels array of channels
	 * @return a lower and an upper bound on the min-entropy leakage of 
	 *         the channel composed in parallel
	 */
	public static double[] estimateParallelMinEntropyLeak(ProbDist jpd, ProbDist apd, Channel[] channels) {
		/* Check whether the number of channels matches with
		   the size of the (prior) input distribution. */
		jpd.consistentChannelsAndPrior(channels.length);
		
		// Case of no composition
		if(channels.length == 1) {
			double MEL = MinEntropy.minEntropyLeak(jpd, channels[0]);
			double[] result = {MEL, MEL};
			return result;
		}
		
		// Check whether the joint distribution jpd is jointly supported
		if(checkJointlySupported && !jpd.isJointlySupported()) {
	    	System.out.println("This tool cannot estimate the measure when the input distrbution is not jointly supported.");
			System.exit(1);
		}
		
		// Calculate MMinInf and MMaxInf for approximate prior
		double[] MInf = MInf(apd, channels.length);
		double MMinInf = MInf[0];		
		double MMaxInf = MInf[1];
		if(verbose >= 5) {
			System.out.print("  MMinInf = " + toString(MMinInf));
			System.out.print("  MMaxInf = " + toString(MMaxInf));
		}

		// Estimate min-entropy leakage of the channel composed in parallel
		double sum = 0.0;
		final int size = jpd.getNumJoint();
		//System.out.println("  size = " + size);
		double[] MEL = new double[size];
		for(int i = 0; i < size; i++) {
			MEL[i] = MinEntropy.minEntropyLeak(jpd.getMarginal(i), channels[i]);
			sum += MEL[i];
		}
		double MELMin = sum - InfoTheory.log2(MMaxInf/MMinInf);
		double MELMax = sum + InfoTheory.log2(MMaxInf/MMinInf);
		if(verbose >= 5) {
			System.out.println("  sum = " + toString(sum));
			System.out.print("  MMaxInf/MMinInf = " + toString(MMaxInf/MMinInf));
			System.out.println("  log2(MMaxInf/MMinInf) = " + toString(InfoTheory.log2(MMaxInf/MMinInf)));
			//System.out.println("  MELMin                = " + toString(MELMin));
			//System.out.println("  MELMax                = " + toString(MELMax));
		}
		double[] result = {Math.max(0.0, MELMin), Math.max(0.0, MELMax)};
		return result;
	}

	/*
	 * TODO: To be completed
	 */
	private static double[] estimateParallelMinEntropyLeakWithIndependentInput(ProbDist[] pds, Channel[] channels) {
		int numPriors = pds.length;
		
		// Case of no composition
		if(numPriors == 1) {
			double MEL = MinEntropy.minEntropyLeak(pds[0], channels[0]);
			double[] result = {MEL, MEL};
			return result;
		}
		
		// Estimate min-entropy leakage of the channel composed in parallel with independent input
		double sum = 0.0;
		for(int i = 0; i < numPriors; i++) {
			sum += MinEntropy.minEntropyLeak(pds[i], channels[i]);
		}
		if(verbose >= 5) {
			//System.out.println("  sum = " + toString(sum));
			//System.out.println("  MELMin                = UNKNOWN");
			//System.out.println("  MELMax                = " + MELMax);
		}
		double[] result = {Math.max(0.0, sum), Math.max(0.0, sum)};
		return result;
	}


	/**
	 * Returns an upper bound on the min-entropy leakage of 
	 * the channel composed in parallel in the case input 
	 * is shared among the channels.
	 * 
	 * @param jpd joint input probability distribution
	 * @param apd approximate joint input probability distribution
	 * @param channels array of channels
	 * @return an upper bound on the min-entropy leakage of 
	 *         the channel composed in parallel
	 */
	public static double[] estimateParallelMinEntropyLeakWithSharedInput(ProbDist jpd, ProbDist apd, Channel[] channels) {
		/* Check whether the number of channels matches with
		   the size of the (prior) input distribution. */
		jpd.consistentChannelsAndPrior(1);

		// Case of no composition
		if(channels.length == 1) {
			double MEL = MinEntropy.minEntropyLeak(jpd, channels[0]);
			double[] result = {MEL, MEL};
			return result;
		}
		
		// Calculate HMinInf and min-entropy
		double hmin = HMinInf(apd);
		double hmax = MinEntropy.minEntropy(apd);

		// Calculate an upper bound for the min-entropy leakage of the channel
		// composed in parallel with shared input value
		final int size = channels.length;
		//System.out.println("  size = " + size);
		double[] MEL = new double[size];
		double sum = 0.0;
		for(int i = 0; i < size; i++) {
			MEL[i] = MinEntropy.minEntropyLeak(jpd, channels[i]);
			if(verbose >= 3) {
				System.out.println("  MEL[" + i + "] = " + MEL[i]);
			}
			sum += MEL[i];
		}
		double MELMax = sum + (channels.length - 1) * (hmin - hmax);
		if(verbose >= 5) {
			System.out.print("  sum = " + toString(sum));
			System.out.print("  channels.length-1 = " + (channels.length - 1));
			System.out.print("  HMinInf = " + toString(hmin));
			System.out.println("  Min-entropy = " + toString(hmax));
			//System.out.println("  MELMin                = UNKNOWN");
			//System.out.println("  MELMax                = " + MELMax);
		}
		double[] result = {UNKNOWN, Math.max(0.0, MELMax)};
		return result;
	}
	
	// TODO: Complete!
	private static double[] estimateParallelMinEntropyLeakConfidenceIntervalVajda(double[] pmf, double[][] matrix, int noOfTests, int[] sampleSizeGivenOutput, int noOfOutputs) {
		double MELMin = 0;
		double MELMax = 0;;
		double[] result = {Math.max(0.0, MELMin), Math.max(0.0, MELMax)};
		return result;
	}


	// TODO: Complete!
	private static double[] estimateParallelMinEntropyLeakConfidenceIntervalBinomial(double[] pmf, double[][] matrix, int[] sampleSizeGivenInput) {
		double MELMin = 0;
		double MELMax = 0;;
		double[] result = {Math.max(0.0, MELMin), Math.max(0.0, MELMax)};
		return result;
	}

	
	//////////////////////////////////////////////
	////// Min-capacity estimation functions /////
	/**
	 * Returns an upper bound on the min-capacity of 
	 * the channel composed in parallel in the case input 
	 * is shared among the channels.
	 * 
	 * @param channels array of channels
	 * @return an upper bound on the min-capacity of 
	 *         the channel composed in parallel
	 */
	public static double[] estimateParallelMinCapacityWithSharedInput(Channel[] channels) {
		// Case of no composition
		if(channels.length == 1) {
			double MEL = MinEntropy.minCapacity(channels[0]);
			double[] result = {MEL, MEL};
			return result;
		}
		
		// Calculate an upper bound for the min-capacity of the channel
		// composed in parallel with shared input value
		final int size = channels.length;
		//System.out.println("  size = " + size);
		double[] MC = new double[size];
		double MCMax = 0.0;
		for(int i = 0; i < size; i++) {
			MC[i] = MinEntropy.minCapacity(channels[i]);
			if(verbose >= 7) {
				System.out.println("  MC[" + i + "] = " + MC[i]);
			}
			MCMax += MC[i];
		}
		double[] result = {UNKNOWN, Math.max(0.0, MCMax)};
		return result;
	}

	

	///////////////////////////////////////////
	////// g-leakage estimation functions /////
	/**
	 * Returns an upper bound on the g-leakage of 
	 * the channel composed in parallel in the case input 
	 * is shared among the channels.
	 * 
	 * @param jpd joint input probability distribution
	 * @param apd approximate joint input probability distribution
	 * @param channels array of channels
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @return an upper bound on the g-leakage of 
	 *         the channel composed in parallel
	 */
	public static double[] estimateParallelGLeakWithSharedInput(ProbDist jpd, ProbDist apd, Channel[] channels, GainFunction gf, Set<String> guessDomain) {
		/* Check whether the number of channels matches with
		   the size of the (prior) input distribution. */
		jpd.consistentChannelsAndPrior(1);

		// Case of no composition
		if(channels.length == 1) {
			double GL = GLeakage.gLeakage(jpd, channels[0], gf, guessDomain);
			double[] result = {GL, GL};
			return result;
		}
		
		// Calculate HgMin and min-entropy
		double hgmin = HgMin(apd, gf, guessDomain);
		double hgmax = GLeakage.gEntropy(apd, gf, guessDomain);

		// Calculate an upper bound for the min-entropy leakage of the channel
		// composed in parallel with shared input value
		final int size = channels.length;
		//System.out.println("  size = " + size);
		double[] GL = new double[size];
		double sum = 0.0;
		for(int i = 0; i < size; i++) {
			GL[i] = GLeakage.gLeakage(jpd, channels[i], gf, guessDomain);
			if(verbose >= 3) {
				System.out.println("  GL[" + i + "] = " + GL[i]);
			}
			sum += GL[i];
		}
		double GLMax = sum + (channels.length - 1) * (hgmin - hgmax);
		if(verbose >= 5) {
			System.out.print("  sum = " + toString(sum));
			System.out.print("  channels.length-1 = " + (channels.length - 1));
			System.out.print("  HgMin = " + toString(hgmin));
			System.out.println("  g-entropy = " + toString(hgmax));
			//System.out.println("  GLMin                = UNKNOWN");
			//System.out.println("  GLMax                = " + GLMax);
		}
		double[] result = {UNKNOWN, Math.max(0.0, GLMax)};
		return result;
	}

	

	////////////////////////////////////
	////// Leakage print functions /////
	/*
	 * Returns the string representing a real number.
	 * 
	 * @param d real number that will be printed
	 * @return the string representing d
	 */
	private static String toString(double d) {
		String str = new String();
		if(d == UNKNOWN) {
			str = "UNKNOWN";
		} else if(d == ERROR) {
			str = "ERROR";
		} else {
			try {
				str = String.format("%1$6.4g", d);
			} catch(Exception ex) {
				System.out.println("Error in reading elements of an input to calculate a projection of a state: " + ex);
				ex.printStackTrace();
				System.out.println("  The file does not follow a prior file (-prior) format.");
				System.exit(1);
			}
		}
		return str;
	}
	
	/**
	 * Chooses to estimate and print one of leakage measures
	 * by compositional reasoning in the case of discrete inputs.
	 * 
	 * @param taskType type of calculation of a leakage measure
	 * @param pds array of probability distributions
	 * @param channels array of channels
	 * @param numChannels the number of channels
	 * @param sampleSize the number of samples
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @param priorShared whether a (prior) input value is shared
	 *        among all channels 
	 * @param compositionalEstimate whether we use the compositional reasoning
	 * @param approxPriorLevel the summation of all probabilities removed from the input distribution
	 * @param approxDoNotKnowChannels whether the analyzer has no knowledge on channel matrices or not
	 */
	public static void printEstimatedMeasure(int taskType, ProbDist[] pds, Channel[] channels, int numChannels, int sampleSize, boolean priorShared, GainFunction gf, Set<String> guessDomain, boolean compositionalEstimate, double approxPriorLevel, boolean approxDoNotKnowChannels) {
		// print the channel/joint matrices
		for(int num = 0; num < channels.length; num++) {
			if(PRINT_CHANNELMATRIX) {
				System.out.println("Channel [" + num + "]:");
				channels[num].printChannel();
				// Print the numbers of inputs, outputs and samples
				if(verbose > 3) {
					System.out.println(channels[num].noOfInputs() + " inputs, " +
									   channels[num].noOfOutputs() + " outputs and " + sampleSize + " samples.\n");
				}
			}
			if(PRINT_JOINTMATRIX) {
				if(priorShared) {
					System.out.println("Joint distribution [" + num + "]:");
					channels[num].printJointMatrix(pds[0]);
					// Print the numbers of inputs, outputs and samples
					if(verbose > 3) {
						System.out.println(channels[num].noOfInputs() + " inputs, " +
										   channels[num].noOfOutputs() + " outputs and " + sampleSize + " samples.\n");
					}
				} else if(channels.length == pds.length) {
					System.out.println("Joint distribution [" + num + "]:");
					channels[num].printJointMatrix(pds[num]);
					// Print the numbers of inputs, outputs and samples
					if(verbose > 3) {
						System.out.println(channels[num].noOfInputs() + " inputs, " +
										   channels[num].noOfOutputs() + " outputs and " + sampleSize + " samples.\n");
					}
				}
			}
		}
		
		// Switch on the kind of the task
		switch(taskType) {
		case(CLC_MUTUAL_INFO):
			//TODO: Complete here!!
			if(correctLeak) {
				//printDiscreteCorrectedMI(pd, channel);
				printToBeSupported("mutual information with correction");
			} else {
				//printDiscreteNonCorrectedMI(pd, channel);
				printToBeSupported("mutual information");
			}
			break;
		case(CLC_CAPACITY):
			//TODO: Complete here!!
			if(correctLeak) {
				//printDiscreteCorrectedChannelCapacity(channel);
				printToBeSupported("capacity with correction");
			} else {
				//printDiscreteNonCorrectedChannelCapacity(channel);
				printToBeSupported("capacity");
			}
			break;
		case(CLC_MIN_ENTROPY):
			if(correctLeak) {
				if(correctLeakNew) {
					System.out.println("Using new correction method...");
					//TestInfoLeak til = new TestInfoLeak();  
					//System.out.println("Lower bound: " + til.getMinEntropyLeakLowerBound(obs));
					//System.out.println("Upper bound: " + til.getMinEntropyLeakUpperBound(obs));
					//TODO: Complete here!!
					//printDiscreteMinEntropyLeakWithNewInterval(pd, channels, sampleSize); // new method
					printToBeSupported("min-entropy leakage with a confidence interval");
				} else {
					System.out.println("Using old correction method...");
					//TODO: Complete here!!
					//printDiscreteMinEntropyLeakWithInterval(pd, channels, sampleSize); //old method
					printToBeSupported("min-entropy leakage with a confidence interval");
				}
			} else {
				printEstimatedDiscreteMinEntropyLeakOnly(pds, channels, priorShared, compositionalEstimate, approxPriorLevel, approxDoNotKnowChannels);
			}
			break;
		case(CLC_MIN_CAPACITY):
			if(correctLeak) {
				printToBeSupported("min-capacity with correction");
			} else {
				printDiscreteMinCapacityOnly(channels, priorShared);
			}
			break;
		case(CLC_G_LEAK):
			printDiscreteGLeakageOnly(pds, channels, gf, guessDomain, priorShared, compositionalEstimate, approxPriorLevel, approxDoNotKnowChannels);
			break;
		}
	}

	
	public static void printExactDiscreteMinEntropyLeakOnly(ProbDist[] pds, Channel[] channels, boolean priorShared) {
		// Print the min-entropy leakage using a compositional reasoning
		//int numPrior = pds.length;
		double result = 0;
		if(readFromPriorFile) {
			if(priorShared)
				result = exactParallelMinEntropyLeakWithSharedInput(pds[0], channels);
			/*
			else if(numPrior > 1)
				result = exactParallelMinEntropyLeakWithIndependentInput(pds, channels);
			 */
			else
				result = exactParallelMinEntropyLeak(pds[0], channels);
			if(result == ERROR) {
				System.out.printf("Error: Failed to calculate min-entropy leakage.");
				//System.out.printf("  MELMin = " + MELMin + "  MELMax" + MELMax);
				return;
			}
			if(verbose == -1) {
				System.out.print(toString(result));
				return;
			}
			System.out.printf("Min-entropy leakage: %s", toString(result));
			if(verbose > 1) {
				double sum = 0;
				if(priorShared) {
					sum = InfoTheory.log2(pds[0].sizeSampleSpace());
				} else {
					for(ProbDist pd : pds) {
						sum += InfoTheory.log2(pd.sizeSampleSpace());
					}
				}
				System.out.printf(" (out of possible %6.4g bits)\n", sum);
				if(verbose > 4) {
					/*
					System.out.println("  -log(a priori vulnerability):     ?");
					System.out.println("  -log(a posteriori vulnerability): ?");
					*/
				}
			}
			System.out.println();
		} else {
			// calculate the size of a uniform joint probability distribution
			int jsize = 1;
			for(Channel channel : channels) {
				jsize *= channel.noOfInputs();
			}
			
			// calculate a uniform joint probability distribution
			String[] jointInputNames = new String[jsize];
			for(int i = 0; i < jsize/channels[0].noOfInputs(); i ++) {
				for(int j = 0; j < channels[0].noOfInputs(); j++) {
					jointInputNames[i * channels[0].noOfInputs() + j] = channels[0].getInputNames()[j];
				}
			}

			int numChannels = channels.length;
			int tmpNumRows = 1;
			for(int num = 0; num < numChannels-1; num++) {
				tmpNumRows *= channels[num].noOfInputs();
		    	//System.out.println("  channels[num+0].noOfInputs() = " + channels[num].noOfInputs());
		    	//System.out.println("  tmpNumRows = " + tmpNumRows);
		    	//System.out.println("  channels[num+1].noOfInputs() = " + channels[num+1].noOfInputs());
		    	//System.out.println("  numRows   = " + numRows);
				jointInputNames = Channel.parallelComposition(jointInputNames, channels[num+1].getInputNames(), tmpNumRows, channels[num+1].noOfInputs(), jsize);
			}
			for(int i = 0; i < jointInputNames.length; i++) {
				jointInputNames[i] = "(" + jointInputNames[i] + ")";
			}

			ProbDist unipd = ProbDist.uniformProbDist(jointInputNames, true);
			result = exactParallelMinEntropyLeak(unipd, channels);

			if(verbose == -1) {
				System.out.print(toString(result));
				return;
			}
			System.out.printf("Min-entropy leakage: %s ", toString(result));
			if(verbose > 1) {
				double sum = 0;
				if(priorShared) {
					sum = InfoTheory.log2(unipd.sizeSampleSpace());
				} else {
					for(ProbDist pd : pds) {
						sum += InfoTheory.log2(unipd.sizeSampleSpace());
					}
				}
				System.out.printf(" (out of possible %6.4g bits)\n", sum);
				System.out.println("  Calculated with the uniform input distribution.");
				if(verbose > 4) {
					/*
					System.out.println("  -log(a priori vulnerability):     ?");
					System.out.println("  -log(a posteriori vulnerability): ?");
					*/
				}
			}
			System.out.println();
		}
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(UNKNOWN);
		upperLimit.add(UNKNOWN);
		confidence.add("NOT SURE   ");
	}


	/*
	 * Estimates and prints the min-entropy leakage
	 * using a compositional reasoning.
	 * 
	 * @param pds array of input probability distributions
	 * @param channels array of channels
	 * @param priorShared whether input is shared among the channels
	 * @param compositionalEstimate whether we use the compositional reasoning
	 * @param approxPriorLevel the summation of all probabilities removed from the input distribution
	 * @param approxDoNotKnowChannels whether the analyzer has no knowledge on channel matrices or not
	 */
	private static void printEstimatedDiscreteMinEntropyLeakOnly(ProbDist[] pds, Channel[] channels, boolean priorShared, boolean compositionalEstimate, double approxPriorLevel, boolean approxDoNotKnowChannels) {
		// optimize approxPriorLevel
		if(approxPriorLevel == APPROX_OPTIMIZED) {
			double maxV = 0.0;
			for(Channel ch : channels) {
				maxV = Math.max(maxV, MinEntropy.conditionalVulnerability(pds[0], ch));
				//System.out.println("  maxV            = " + maxV);
			}
			approxPriorLevel = maxV / 3.0;
			if(verbose >= 5) {
				System.out.println("  approxPriorLevel (maxV/3) = " + approxPriorLevel);
			}
		}
		
		// approximate joint input
		ProbDist apd;
		if(compositionalEstimate && approxPriorLevel >= 1) {
			apd = ApproxPrior.approxPriorSmallProbsRemoved(pds[0], true);
			approxPriorLevel = ApproxPrior.sumOfProbsRemoved(apd);
		} else if(compositionalEstimate && approxPriorLevel > 0) {
			//System.out.println("  approxPriorLevel (opt) = " + approxPriorLevel);
			apd = ApproxPrior.approxPriorSmallProbsRemoved(pds[0], approxPriorLevel, true);
			approxPriorLevel = ApproxPrior.sumOfProbsRemoved(apd);
		} else {
			apd = pds[0];
			approxPriorLevel = 0.0;
		}
		if(verbose >= 5) {
			System.out.println("  approxPriorLevel = " + approxPriorLevel);
		}
		if(!approxDoNotKnowChannels) {
			pds[0] = apd;
		}
		
		// Evalulating an error introduced by input approximation 
		double[] errorApproxMeasure = new double[2];
		if(compositionalEstimate && approxPriorLevel > 0) {
			if(approxDoNotKnowChannels) {
				if(priorShared) {
					errorApproxMeasure = ApproxPrior.errorMinEntropyLeakSmallProbsRemovedNoReexecutionWithSharedInput(pds[0], channels, approxPriorLevel);
				} else {
					errorApproxMeasure = ApproxPrior.errorMinEntropyLeakSmallProbsRemovedNoReexecutionWithJointInput(pds[0], channels, approxPriorLevel);
				}
			} else {
				errorApproxMeasure = ApproxPrior.errorMinEntropyLeakSmallProbsRemoved(pds[0], channels, approxPriorLevel);
			}
		} else {
			errorApproxMeasure[0] = 0;
			errorApproxMeasure[1] = 0;
		}
		if(verbose >= 5) {
			System.out.printf("  errorApproxMeasure = [ %s, %s ]", toString(errorApproxMeasure[0]), toString(errorApproxMeasure[1]));
			System.out.println();
		}

		// Print the min-entropy leakage using a compositional reasoning
		int numPrior = pds.length;
		double result[] = new double[2];
		double MELMin = 0;
		double MELMax = 0;
		if(readFromPriorFile) {
			if(priorShared)
				result = estimateParallelMinEntropyLeakWithSharedInput(pds[0], apd, channels);
			else if(numPrior > 1)
				result = estimateParallelMinEntropyLeakWithIndependentInput(pds, channels);
			else
				result = estimateParallelMinEntropyLeak(pds[0], apd, channels);
			MELMin = result[0];
			MELMax = result[1];
			if(result[0] == ERROR || result[1] == ERROR) {
				System.out.printf("Error: Failed to calculate min-entropy leakage.");
				//System.out.printf("  MELMin = " + MELMin + "  MELMax" + MELMax);
				return;
			}
			if(verbose == -1) {
				System.out.print(toString(MELMax+errorApproxMeasure[1]));
				return;
			}
			if(verbose >= 5) {
				System.out.println("  MELMin = " + MELMin);
				System.out.println("  MELMax = " + MELMax);
				System.out.println();
			}
			System.out.printf("Min-entropy leakage: [ %s, %s ] ", toString(Math.max(0, MELMin+errorApproxMeasure[0])), toString(Math.max(0, MELMax+errorApproxMeasure[1])));
			if(verbose > 1) {
				double sum = 0;
				if(priorShared) {
					sum = InfoTheory.log2(pds[0].sizeSampleSpace());
				} else {
					for(ProbDist pd : pds) {
						sum += InfoTheory.log2(pd.sizeSampleSpace());
					}
				}
				System.out.printf(" (out of possible %6.4g bits)\n", sum);
				if(verbose > 4) {
					/*
					System.out.println("  -log(a priori vulnerability):     ?");
					System.out.println("  -log(a posteriori vulnerability): ?");
					*/
				}
			}
			System.out.println();
		} else {
			// calculate the size of a uniform joint probability distribution
			int jsize = 1;
			for(Channel channel : channels) {
				jsize *= channel.noOfInputs();
			}
			
			// calculate a uniform joint probability distribution
			String[] jointInputNames = new String[jsize];
			for(int i = 0; i < jsize/channels[0].noOfInputs(); i ++) {
				for(int j = 0; j < channels[0].noOfInputs(); j++) {
					jointInputNames[i * channels[0].noOfInputs() + j] = channels[0].getInputNames()[j];
				}
			}

			int numChannels = channels.length;
			int tmpNumRows = 1;
			for(int num = 0; num < numChannels-1; num++) {
				tmpNumRows *= channels[num].noOfInputs();
		    	//System.out.println("  channels[num+0].noOfInputs() = " + channels[num].noOfInputs());
		    	//System.out.println("  tmpNumRows = " + tmpNumRows);
		    	//System.out.println("  channels[num+1].noOfInputs() = " + channels[num+1].noOfInputs());
		    	//System.out.println("  numRows   = " + numRows);
				jointInputNames = Channel.parallelComposition(jointInputNames, channels[num+1].getInputNames(), tmpNumRows, channels[num+1].noOfInputs(), jsize);
			}
			for(int i = 0; i < jointInputNames.length; i++) {
				jointInputNames[i] = "(" + jointInputNames[i] + ")";
			}

			ProbDist unipd = ProbDist.uniformProbDist(jointInputNames, true);
			result = estimateParallelMinEntropyLeak(unipd, unipd, channels);
			MELMin = result[0];
			MELMax = result[1];

			if(verbose == -1) {
				System.out.print(toString(MELMax));
				return;
			}
			System.out.printf("Min-entropy leakage: [ %s, %s ] ", toString(MELMin), toString(MELMax));
			if(verbose > 1) {
				double sum = 0;
				if(priorShared) {
					sum = InfoTheory.log2(channels[0].noOfInputs());
				} else {
					sum = InfoTheory.log2(unipd.sizeSampleSpace());
				}
				System.out.printf(" (out of possible %6.4g bits)\n", sum);
				System.out.println("  Calculated with the uniform input distribution.");
				if(verbose > 4) {
					/*
					System.out.println("  -log(a priori vulnerability):     ?");
					System.out.println("  -log(a posteriori vulnerability): ?");
					*/
				}
			}
			System.out.println();
		}
		
		leakage.add(UNKNOWN);
		zeroLimit.add(ERROR);
		lowerLimit.add(MELMin);
		upperLimit.add(MELMax);
		confidence.add("NOT SURE   ");
	}

	
	/*
	 * Estimates and prints the min-entropy leakage
	 * using a compositional reasoning.
	 * 
	 * @param pds array of input probability distributions
	 * @param channels array of channels
	 * @param priorShared whether input is shared among the channels
	 */
	private static void printDiscreteMinCapacityOnly(Channel[] channels, boolean priorShared) {
		// Print the min-capacity using a compositional reasoning
		double result[] = new double[2];
		double MCMin = 0;
		double MCMax = 0;
		if(priorShared)
			result = estimateParallelMinCapacityWithSharedInput(channels);
		/*
		else
			result = estimateParallelMinCapacity(channels);
		*/
		MCMin = result[0];
		MCMax = result[1];
		if(result[0] == ERROR || result[1] == ERROR) {
			System.out.printf("Error: Failed to calculate min-capacity.");
			//System.out.printf("  MELMin = " + MELMin + "  MELMax" + MELMax);
			return;
		}
		if(verbose == -1) {
			System.out.print(toString(result[1]));
			return;
		}
		System.out.printf("Min-capacity: [ %s, %s ] ", toString(MCMin), toString(MCMax));
		if(verbose > 1) {
			double sum = 0;
			if(priorShared) {
				sum = InfoTheory.log2(channels[0].noOfInputs());
			} else {
				for(Channel ch : channels) {
					sum += InfoTheory.log2(ch.noOfInputs());
				}
			}
			System.out.printf(" (out of possible %6.4g bits)\n", sum);
		}
		System.out.println();
		
		leakage.add(UNKNOWN);
		zeroLimit.add(ERROR);
		lowerLimit.add(UNKNOWN);
		upperLimit.add(MCMax);
		confidence.add("NOT SURE   ");
	}

	
	/*
	 * Estimates and prints the g-leakage using a compositional reasoning.
	 * 
	 * @param pds array of input probability distributions
	 * @param channels array of channels
	 * @param gf gain function
	 * @param guessDomain the set of all guesses
	 * @param priorShared whether input is shared among the channels
	 * @param compositionalEstimate whether we use the compositional reasoning
	 * @param approxPriorLevel the summation of all probabilities removed from the input distribution
	 * @param approxDoNotKnowChannels whether the analyzer has no knowledge on channel matrices or not
	 */
	private static void printDiscreteGLeakageOnly(ProbDist[] pds, Channel[] channels, GainFunction gf, Set<String> guessDomain, boolean priorShared, boolean compositionalEstimate, double approxPriorLevel, boolean approxDoNotKnowChannels) {
		// optimize approxPriorLevel
		if(approxPriorLevel == APPROX_OPTIMIZED) {
			// TODO: to be completed
			/*
			double maxV = 0.0;
			for(Channel ch : channels) {
				maxV = Math.max(maxV, InfoTheory.conditionalVulnerability(pds[0], ch));
				//System.out.println("  maxV            = " + maxV);
			}
			approxPriorLevel = maxV / 3.0;
			if(verbose >= 5) {
				System.out.println("  approxPriorLevel (maxV/3) = " + approxPriorLevel);
			}
			*/
		}
		
		// approximate joint input
		ProbDist apd;
		// TODO: to be completed
		apd = pds[0];
		/*
		if(compositionalEstimate && approxPriorLevel >= 1) {
			apd = ApproxPrior.approxPriorSmallProbsRemoved(pds[0], true);
			approxPriorLevel = ApproxPrior.sumOfProbsRemoved(apd);
		} else if(compositionalEstimate && approxPriorLevel > 0) {
			//System.out.println("  approxPriorLevel (opt) = " + approxPriorLevel);
			apd = ApproxPrior.approxPriorSmallProbsRemoved(pds[0], approxPriorLevel, true);
			approxPriorLevel = ApproxPrior.sumOfProbsRemoved(apd);
		} else {
			apd = pds[0];
			approxPriorLevel = 0.0;
		}
		if(verbose >= 5) {
			System.out.println("  approxPriorLevel = " + approxPriorLevel);
		}
		if(!approxDoNotKnowChannels) {
			pds[0] = apd;
		}
		*/
		
		// Evalulating an error introduced by input approximation 
		double[] errorApproxMeasure = new double[2];
		errorApproxMeasure[0] = 0;
		errorApproxMeasure[1] = 0;
		// TODO: to be completed
		/*
		if(compositionalEstimate && approxPriorLevel > 0) {
			if(approxDoNotKnowChannels) {
				if(priorShared) {
					errorApproxMeasure = ApproxPrior.errorMinEntropyLeakSmallProbsRemovedNoReexecutionWithSharedInput(pds[0], channels, approxPriorLevel);
				} else {
					errorApproxMeasure = ApproxPrior.errorMinEntropyLeakSmallProbsRemovedNoReexecutionWithJointInput(pds[0], channels, approxPriorLevel);
				}
			} else {
				errorApproxMeasure = ApproxPrior.errorMinEntropyLeakSmallProbsRemoved(pds[0], channels, approxPriorLevel);
			}
		} else {
			errorApproxMeasure[0] = 0;
			errorApproxMeasure[1] = 0;
		}
		if(verbose >= 5) {
			System.out.printf("  errorApproxMeasure = [ %s, %s ]", toString(errorApproxMeasure[0]), toString(errorApproxMeasure[1]));
			System.out.println();
		}
		*/

		// Print the min-entropy leakage using a compositional reasoning
		int numPrior = pds.length;
		double result[] = new double[2];
		double GLMin = 0;
		double GLMax = 0;
		if(readFromPriorFile) {
			if(priorShared)
				result = estimateParallelGLeakWithSharedInput(pds[0], apd, channels, gf, guessDomain);
			else if(numPrior > 1)
				result = null; // TODO: make a new method
			else
				result = null;  // TODO: make a new method
			GLMin = result[0];
			GLMax = result[1];
			if(result == null || result[0] == ERROR || result[1] == ERROR) {
				System.out.printf("Error: Failed to calculate g-leakage.");
				//System.out.printf("  GLMin = " + GLMin + "  GLMax" + GLMax);
				return;
			}
			if(verbose == -1) {
				System.out.print(toString(GLMax+errorApproxMeasure[1]));
				return;
			}
			if(verbose >= 5) {
				System.out.println("  GLMin = " + GLMin);
				System.out.println("  GLMax = " + GLMax);
				System.out.println();
			}
			System.out.printf("g-leakage: [ %s, %s ] ", toString(Math.max(0, GLMin+errorApproxMeasure[0])), toString(Math.max(0, GLMax+errorApproxMeasure[1])));
			if(verbose > 1) {
				double sum = 0;
				if(priorShared) {
					sum = InfoTheory.log2(pds[0].sizeSampleSpace());
				} else {
					for(ProbDist pd : pds) {
						sum += InfoTheory.log2(pd.sizeSampleSpace());
					}
				}
				System.out.printf(" (out of possible %6.4g bits)\n", sum);
				if(verbose > 4) {
					/*
					System.out.println("  -log(a priori vulnerability):     ?");
					System.out.println("  -log(a posteriori vulnerability): ?");
					*/
				}
			}
			System.out.println();
		} else {
			// calculate the size of a uniform joint probability distribution
			int jsize = 1;
			for(Channel channel : channels) {
				jsize *= channel.noOfInputs();
			}
			
			// calculate a uniform joint probability distribution
			String[] jointInputNames = new String[jsize];
			for(int i = 0; i < jsize/channels[0].noOfInputs(); i ++) {
				for(int j = 0; j < channels[0].noOfInputs(); j++) {
					jointInputNames[i * channels[0].noOfInputs() + j] = channels[0].getInputNames()[j];
				}
			}

			int numChannels = channels.length;
			int tmpNumRows = 1;
			for(int num = 0; num < numChannels-1; num++) {
				tmpNumRows *= channels[num].noOfInputs();
		    	//System.out.println("  channels[num+0].noOfInputs() = " + channels[num].noOfInputs());
		    	//System.out.println("  tmpNumRows = " + tmpNumRows);
		    	//System.out.println("  channels[num+1].noOfInputs() = " + channels[num+1].noOfInputs());
		    	//System.out.println("  numRows   = " + numRows);
				jointInputNames = Channel.parallelComposition(jointInputNames, channels[num+1].getInputNames(), tmpNumRows, channels[num+1].noOfInputs(), jsize);
			}
			for(int i = 0; i < jointInputNames.length; i++) {
				jointInputNames[i] = "(" + jointInputNames[i] + ")";
			}

			ProbDist unipd = ProbDist.uniformProbDist(jointInputNames, true);
			result = estimateParallelMinEntropyLeak(unipd, unipd, channels);
			GLMin = result[0];
			GLMax = result[1];

			if(verbose == -1) {
				System.out.print(toString(GLMax));
				return;
			}
			System.out.printf("g-leakage: [ %s, %s ] ", toString(GLMin), toString(GLMax));
			if(verbose > 1) {
				System.out.printf(" (out of possible %6.4g bits)\n",
						          InfoTheory.log2(unipd.sizeSampleSpace()));
				System.out.println("  Calculated with the uniform input distribution.");
				if(verbose > 4) {
					/*
					System.out.println("  -log(a priori vulnerability):     ?");
					System.out.println("  -log(a posteriori vulnerability): ?");
					*/
				}
			}
			System.out.println();
		}
		
		leakage.add(UNKNOWN);
		zeroLimit.add(ERROR);
		lowerLimit.add(GLMin);
		upperLimit.add(GLMax);
		confidence.add("NOT SURE   ");
	}


	/*
	 * Prints a comment that the functionality is not supported.
	 * 
	 * @param comment comment on the unsupported functionality
	 */
	private static void printToBeSupported(String comment) {
		System.out.print("This functionality is not supported.");
		System.out.println("  (" + comment + ")");
	}


	/*
	 * Unneccesary method
	 * 
	 * @param pd array of input probability distributions
	 * @param channels array of channels
	 * @return the exact value of the min-entropy leakage of 
	 *         the channel composed in parallel
	 */
	/*
	private static double exactParallelMinEntropyLeakWithIndependentInput(ProbDist[] pd, Channel[] channels) {
		// size of the composed channel matrix
		int numRowsComposedMatrix = 1;
		int numColsComposedMatrix = 1;
		for(int num = 0; num < channels.length; num++) {
			numRowsComposedMatrix *= channels[num].noOfInputs();
			numColsComposedMatrix *= channels[num].noOfOutputs();
		}
		
		// Calculate the input names of the composed channel
		String[] composedInputNames = new String[numRowsComposedMatrix];
		for(int i = 0; i < channels[0].noOfInputs(); i++) {
			composedInputNames[i] = channels[0].getInputNames()[i];
		}
		int tmpNumRows = 1;
		for(int num = 0; num < channels.length-1; num++) {
			tmpNumRows *= channels[num].noOfInputs();
	    	//System.out.println("  channels[num+0].noOfInputs() = " + channels[num].noOfInputs());
	    	//System.out.println("  tmpNumRows = " + tmpNumRows);
	    	//System.out.println("  channels[num+1].noOfInputs() = " + channels[num+1].noOfInputs());
	    	//System.out.println("  numRows   = " + numRows);
			composedInputNames = Channel.parallelComposition(composedInputNames, channels[num].getInputNames(), tmpNumRows, channels[num+1].noOfInputs(), numRowsComposedMatrix);
		}
		for(int i = 0; i < composedInputNames.length; i++) {
			composedInputNames[i] = "(" + composedInputNames[i] + ")";
		}

		// input probability distribution array
		ArrayList<double[]> pmfs = new ArrayList<double[]>();
		for(int num = 0; num < channels.length; num++) {
			double[] pmf = pd[num].probDistToPMFArray(channels[num].getInputNames());
			pmfs.add(pmf);
		}
		
		// initialize composedInputIndex and composedOutputIndex
		initializeIndex(channels.length);

		// initialize maxJointCol
		double[] maxJointCol = new double[numColsComposedMatrix];
		for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
			maxJointCol[colComposed] = 0;
		}

		//System.out.println("  numColsComposedMatrix = " + numColsComposedMatrix);
		//System.out.println("  pmf.length = " + pmf.length);
		for(int rowComposed = 0; rowComposed < numRowsComposedMatrix; rowComposed++) {
			for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
				// conditional probability of the composed channel
				double condProb = 1;
				for(int num = 0; num < channels.length; num++) {
					int row = composedInputIndex[num];
					int col = composedOutputIndex[num];
					//System.out.print("  rowComposed = " + rowComposed);
					//System.out.print("  colComposed = " + colComposed);
					//System.out.print("  row = " + row);
					//System.out.print("  col = " + col);
					//System.out.print("  num = " + num);
					condProb *= channels[num].getMatrix()[row][col];
					//System.out.print("  cp = " + condProb + " ||");
				}
				
				// joint input probability
				double inputProb = 1;
				for(int num = 0; num < channels.length; num++) {
					int row = composedInputIndex[num];
					inputProb *= pmfs.get(num)[row];
				}
				
				double jointProb = inputProb * condProb;
				//System.out.print("  joint = " + jointProb);
				maxJointCol[colComposed] = Math.max(maxJointCol[colComposed], jointProb);
				//System.out.println("  maxJointCol = " + maxJointCol[colComposed]);
				incrementComposedOutputIndex(channels);
			}
			incrementComposedInputIndex(channels);
		}

		// Calculate the conditional min-entropy
		double conditionalMinEntropy = 0;
		for(int colComposed = 0; colComposed < numColsComposedMatrix; colComposed++) {
			conditionalMinEntropy += maxJointCol[colComposed];
			//System.out.println("  conditional = " + conditionalMinEntropy);
		}
		conditionalMinEntropy = -InfoTheory.log2(conditionalMinEntropy);

		// Calculate min-entropy
		double minEntropy = 0;
		for(int num = 0; num < pd.length; num++) {
			minEntropy = InfoTheory.minEntropy(pd[num]);
		}
		
		double result = minEntropy - conditionalMinEntropy;
		return result;
	}
	*/
}
