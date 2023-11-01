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
 * Copyright 2014 Tom Chothia, Yusuke Kawamoto and Chris Novakovic
 */
package bham.leakiest.infotheory;

import java.util.ArrayList;
import java.util.Collections;
import bham.leakiest.*;
import bham.leakiest.comparator.*;

/**
 * This is a library of useful information theory definitions related
 * to min-entropy-based information measure. <br>
 *
 * Probability Mass Functions are represented by an array of doubles
 * p(element i) = pmf[i] or by ProbDist class. <br>
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.4.1
 */
public class MinEntropy {
	// Verbose
	private static int verbose = TestInfoLeak.verbose;

	/**
	 * Base when computing the logarithms.
	 */
	public static final int base_log = 2;
	private static final int ERROR = -1;
	

	/**
	 * Calculates the vulnerability of a PMF.
	 * <BR>
	 * V_inf(pmf) = max_i(pmf[i])
	 * 
	 * @param pmf PMF array
	 * @return The vulnerability of pmf
	 * @deprecated This method should be replaced with another method {@link #vulnerability(ProbDist)}
	 */
	public static double vulnerability(double[] pmf) {
		double maxProb = 0;
		for(int i = 0; i < pmf.length; i++) {
			maxProb = Math.max(maxProb, pmf[i]);
		}
		return Math.min(maxProb, 1);
	}
	
	/**
	 * Calculates the min-entropy of a PMF.
	 * <BR>
	 * H_inf(pmf) = -log( max_i(pmf[i]) )
	 * 
	 * @param pmf PMF array
	 * @return The min-entropy of pmf
	 * @deprecated This method should be replaced with another method {@link #minEntropy(ProbDist)}
	 */
	public static double minEntropy(double[] pmf) {
		return -InfoTheory.log(vulnerability(pmf), InfoTheory.base_log);
	}
	
	/**
	 * Calculates the vulnerability of a probability distribution.
	 * <BR>
	 * V_inf(pd) = max_i(pd[i])
	 * 
	 * @param pd probability distribution
	 * @return The vulnerability of pd
	 */
	public static double vulnerability(ProbDist pd) {
		double maxProb = 0;
		for(State st : pd.getStatesCollection()) {
			double prob = pd.getProb(st);
			maxProb = Math.max(maxProb, prob);
		}
		return Math.min(maxProb, 1);
	}

	/**
	 * Calculates the min-entropy of a probability distribution.
	 * <BR>
	 * H_inf(pd) = -log( max_i(pd[i]) )
	 * 
	 * @param pd probability distribution
	 * @return The min-entropy of pd
	 */
	public static double minEntropy(ProbDist pd) {
		return -InfoTheory.log(vulnerability(pd), base_log);
	}

	/*
	 * Calculates the conditional vulnerability of a joint probability distribution.
	 * @param matrix joint probability matrix
	 * @return The conditional vulnerability of the given matrix
	 */
	private static double conditionalVulnerability(double[][] jointProbMatrix) {
		double posteriori = 0;
		for(int j = 0; j < jointProbMatrix[0].length; j++) {
			double maxProb = 0;
			for(int i = 0; i < jointProbMatrix.length; i++) {
				maxProb = Math.max(maxProb, jointProbMatrix[i][j]);
			}
			//System.out.printf(" Posteriori = %6.4f", posteriori);
			posteriori += maxProb;
			//System.out.printf(" => %6.4f", posteriori);
			//System.out.println();
		}
		//System.out.println("-log2(posterior) = " + InfoTheory.log2(posteriori));
		return posteriori;
	}

	/**
	 * Calculates the conditional vulnerability of a probability distribution
	 * given a channel matrix.
	 * @param pmf PMF array
	 * @param matrix channel matrix
	 * @return The conditional vulnerability of pmf given matrix
	 * @deprecated This method should be replaced with another method {@link #conditionalVulnerability(ProbDist, Channel)}
	 */
	public static double conditionalVulnerability(double[] pmf, double[][] matrix) {
		double posteriori = 0;
		for(int j = 0; j < matrix[0].length; j++) {
			double maxProb = 0;
			//System.out.println(" ------");
			for(int i = 0; i < pmf.length; i++) {
				//System.out.printf("  pmf[i] = %6.4f * matrix[%d][%d] = %6.4f = %6.4f", pmf[i], i, j, matrix[i][j], (pmf[i]*matrix[i][j]));
				//System.out.printf("  maxProb = %6.4f", maxProb);
				maxProb = Math.max(maxProb, pmf[i] * matrix[i][j]);
				//System.out.printf(" => %6.4f", maxProb);
				//System.out.println();
			}
			//System.out.printf(" Posteriori = %6.4f", posteriori);
			posteriori += maxProb;
			//System.out.printf(" => %6.4f", posteriori);
			//System.out.println();
		}
		//System.out.println("-log2(posterior) = " + InfoTheory.log2(posteriori));
		return posteriori;
	}

	/**
	 * Calculates the conditional vulnerability of a probability distribution
	 * given a channel.
	 * 
	 * @param pd prbability distribution
	 * @param channel channel
	 * @return The conditional vulnerability of pd given channel
	 */
	public static double conditionalVulnerability(ProbDist pd, Channel channel) {
		double[] pmf = pd.probDistToPMFArray(channel.getInputNames());
		double[][] matrix = channel.getMatrix();
		if(pmf != null)
			return conditionalVulnerability(pmf, matrix);
		else
			return (double)ERROR;
	}

	/**
	 * Calculates the conditional min-entropy of a probability distribution.
	 * <BR>
	 * H_inf(pmf|Y) = -log( &Sigma;_y max_x pmf[x] matrix[y|x] )
	 * @param pmf PMF array
	 * @param matrix channel matrix array
	 * @return The conditional min-entropy of matrix
	 *         given an input PMF array pmf 
	 * @deprecated This method should be replaced with another method {@link #conditionalMinEntropy(ProbDist, Channel)}
	 */
	public static double conditionalMinEntropy(double[] pmf, double[][] matrix) {
		double posteriori = conditionalVulnerability(pmf, matrix);
		return - InfoTheory.log(Math.min(posteriori, 1), InfoTheory.base_log);
	}

	/**
	 * Calculates the conditional min-entropy of a probability distribution.
	 * 
	 * @param pd prbability distribution
	 * @param channel channel
	 * @return The conditional min-entropy of channel
	 *         given an input probability distribution pd 
	 */
	public static double conditionalMinEntropy(ProbDist pd, Channel channel) {
		double[] pmf = pd.probDistToPMFArray(channel.getInputNames());
		double[][] matrix = channel.getMatrix();
		if(pmf != null)
			return conditionalMinEntropy(pmf, matrix);
		else
			return (double)InfoTheory.ERROR;
	}

	/**
	 * Calculates the min-entropy leakage from a channel
	 * given an initial uncertainty pmf.
	 * <BR>
	 * L(pmf,Y) = H_inf(pmf) - H_inf(pmf|Y)
	 * @param pmf PMF array
	 * @param matrix channel matrix array
	 * @return The min-entropy leakage from matrix given an initial PMF pmf
	 * @deprecated This method should be replaced with another method {@link #minEntropyLeak(ProbDist, Channel)}
	 */
	public static double minEntropyLeak(double[] pmf, double[][] matrix) {
		//System.out.println(" H(pmf) =        " + minEntropy(pmf));
		//System.out.println(" H(pmf, matrix) = " + conditionalMinEntropy(pmf, matrix));
		return Math.max(0.0, MinEntropy.minEntropy(pmf) - conditionalMinEntropy(pmf, matrix));
	}

	/**
	 * Calculates the min-entropy leakage from a channel
	 * given an input probability distribution pd.
	 * <BR>
	 * L(pd,Y) = H_inf(pd) - H_inf(pd|Y)
	 * @param pd prbability distribution
	 * @param channel channel
	 * @return The min-entropy leakage from channel
	 *         given an input probability distribution pd
	 */
	public static double minEntropyLeak(ProbDist pd, Channel channel) {
		double[] pmf = pd.probDistToPMFArray(channel.getInputNames());
		double[][] matrix = channel.getMatrix();
		if(pmf != null)
			return minEntropyLeak(pmf, matrix);
		else
			return (double)InfoTheory.ERROR;
	}


	/////////////////////////////////////////////////////////////////////////
	// Confidence interval for min-entropy leakage, based on previous work //
	/**
	 * Calculates the maximum possible error of
	 * the estimated min-entropy leakage.
	 * 
	 * @param pmf pmf array
	 * @param matrix channel matrix
	 * @param noOfTests the sample size
	 * @param noOfOutputs the number of outputs
	 * @return the maximum possible error of the estimated min-entropy leakage 
	 * @deprecated This function is based on the lemma ver20130114 and should not use any more.
	 *             This method should be replaced with another method.
	 */
	public static double minEntropyLeakError20130114(double[] pmf, double[][] matrix, int noOfTests, int noOfOutputs) {
		double S = 0.05;
	
		// Calculate the accuracy e0 for V(X)
		double e0 = Math.sqrt( 2 * (1-InfoTheory.log2(S)) / ((double)noOfTests * InfoTheory.log2(Math.E)) );
	
		// Calculate V(X)
		double vx = 0;
		for(int i = 0; i < pmf.length; i++)
			vx = Math.max(vx, pmf[i]);
		vx = Math.min(vx, 1);
		
		// Calculate the accuracy e1 for min-entropy
		double e1;
		if(vx > e0)
			e1 = Math.max(InfoTheory.log2(1 + e0 / vx), -InfoTheory.log2(1 - e0 / vx));
		else 
			e1 = InfoTheory.log2(1 + e0 / vx);
		//System.out.println("  S: " + S + "  e0: " + e0 + "  vx: " + vx + "  e1: " + e1);
		//System.out.println("  1 + e0 / vx: " + (1 + e0 / vx) + "  1 - e0 / vx: " + (1 - e0 / vx));
		//System.out.println("  log2(1 + e0 / vx): " + log2(1 + e0 / vx) + "  log2(1 - e0 / vx): " + log2(1 - e0 / vx));
		//System.out.println("");
	
		// Calculate the accuracy e2 for V(X|Y)
		double e2 = noOfOutputs * Math.sqrt( 2 * (1-InfoTheory.log2(S)) / ((double)noOfTests * InfoTheory.log2(Math.E)) );
	
		// Calculate V(X|Y)
		double vxy = 0;
		for(int j = 0; j < matrix[0].length; j++) {
			double maxProb = 0;
			for(int i = 0; i < pmf.length; i++) {
				maxProb = Math.max(maxProb, pmf[i] * matrix[i][j]);
			}
			vxy += maxProb;
		}
		vxy = Math.min(vxy, 1);
		
		// Calculate the accuracy e3 for conditional min-entropy
		double e3;
		if(vxy > e2)
			e3 = Math.max(InfoTheory.log2(1 + e2 / vxy), -InfoTheory.log2(1 - e2 / vxy));
		else
			e3 = InfoTheory.log2(1 + e2 / vxy);
		//System.out.println("  e2: " + e2 + "  vxy: " + vxy + "  e3: " + e3);
		//System.out.println("  1 + e2 / vxy: " + (1 + e2 / vxy) + "  1 - e2 / vxy: " + (1 - e2 / vxy));
		//System.out.println("  log2(1 + e2 / vxy): " + log2(1 + e2 / vxy) + "  log2(1 - e2 / vxy): " + log2(1 - e2 / vxy));
	
		return e3;
	}

	/**
	 * Calculates the lower bound of the confidence interval of
	 * the estimated min-entropy leakage using information-theoretic
	 * bounds presetend in [Vajda'02] &amp; [Dutta, Goswami'10].
	 * 
	 * @param pmf pmf array
	 * @param matrix channel matrix
	 * @param noOfTests the sample size
	 * @param sampleSizeGivenOutput the sample size given an output
	 * @param noOfOutputs the number of outputs
	 * @return the confidence interval of the estimated min-entropy leakage 
	 */
	public static double[] minEntropyLeakConfidenceIntervalVajda(double[] pmf, double[][] matrix, int noOfTests, int[] sampleSizeGivenOutput, int noOfOutputs) {
		// Confidence level
		final double confidenceLevel = 0.975;
		final double confidenceLevelGivenOutput = Math.pow(confidenceLevel, 1.0/(double)matrix[0].length);
		//System.out.println("confidenceLevel(y) = " + confidenceLevelGivenOutput);
		
		// Calculate initial error1 (based on [Vajda'02])
		final double cl1 = Math.sqrt(confidenceLevelGivenOutput);   // assuming cl1 == cl2
		//final double cl1 = Math.pow(confidenceLevelGivenOutput, 0.975);
		//final double cl1 = Math.pow(confidenceLevelGivenOutput, 0.002);
		final double tmp1 = Math.log(2.0 / (1 - cl1));
		final double Ly = (double)noOfTests / (double)matrix[0].length;  // approximation for initial value
		double error1 = Math.sqrt(2.0 / Ly * tmp1);
		//System.out.println("cl1 = " + cl1);
		if(InfoTheory.verbose >= 7) {
			System.out.println("noTest" + noOfTests);
			System.out.println("mat   " + matrix[0].length);
			System.out.println("Ly =  " + Ly);
		}
		//System.out.println("error1 = " + error1);
		
		// Calculate initial error2 (based on [Dutta, Goswami'10])
		final double cl2 = confidenceLevelGivenOutput / cl1;
		double tmp2 = Math.log(2.0 / (1.0 - cl2));
		double error2 = (double)(4 * tmp2 + Math.sqrt(16 * tmp2 * tmp2 + 72 * noOfTests * tmp2)) / (double)(12 * noOfTests);
		//System.out.println("cl2 = " + cl2);
		//System.out.println("error2 = " + error2);
	
		// Improve error1 and error2
		final double accuracy = 0.01;
		double productOfcl = 1;
		int loop = 0;
		while(Math.abs(productOfcl - confidenceLevel) > accuracy ) {
			// Initialise
			productOfcl = 1;
			int sign = -1;
			loop++;
			//System.out.println("  error1 = " + error1);
			//System.out.println("  error2 = " + error2);
			//System.out.println("  loop   = " + loop);
	
			// Check the value of confidence level
			for(int j = 0; j < matrix[0].length; j++) {
				double cy1 = 1 - 2 * Math.exp(- sampleSizeGivenOutput[j] * error1 * error1/ 2.0);
				double cy2 = 1 - 2 * Math.exp(- 6 * noOfTests * error2 * error2 / (3.0 + 4 * error2));
				productOfcl *= cy1 * cy2;
				//System.out.println("  cy1     = " + cy1);
				//System.out.println("  cy2     = " + cy2);
			}
			//System.out.println("  productOfcl = " + productOfcl);
			//System.out.println("--------------------");
			if(productOfcl < confidenceLevel) {
				error1 += accuracy;
				if(sign == 0) break;
				sign = 1;
			} else {
				error1 -= accuracy;
				if(sign == 1) break;
				sign = 0;
			}
		}
		//System.out.println("  error1 = " + error1);
		//System.out.println("  error2 = " + error2);
		//System.out.println("  H(x)   = " + minEntropy(pmf));
	
		// Calculate the mariginal output probability distribution P_Y
		double outputdist[] = InfoTheory.outputDist(pmf, matrix);
		
		// Calculate the empirical max_x p(x|y) for each y
		double max_xy[] = new double[matrix[0].length];
		for(int j = 0; j < matrix[0].length; j++) {
			max_xy[j] = 0;
			for(int i = 0; i < pmf.length; i++) {
				max_xy[j] = Math.max(max_xy[j], pmf[i] * matrix[i][j] / outputdist[j]);
			}
		}
	
		// Calculate the lower bound for max_x p(x,y) for each y
		double lower = 0;
		for(int j = 0; j < matrix[0].length; j++) {
			lower += Math.max(0.0, (max_xy[j] - error1)) * Math.max(0.0, outputdist[j] - error2);
			//System.out.println("  lower = " + lower);
		}
		//System.out.println("  lower = " + lower);
		double MELMin = Math.max(0.0, MinEntropy.minEntropy(pmf) + InfoTheory.log2(lower));
		//System.out.println("  log(lw)= " + log2(lower));
		//System.out.println("  MELMin = " + MELMin);
		if(Double.isNaN(MELMin))
			MELMin = 0.0;
	
		// Calculate the upper bound for max_x p(x,y) for each y
		double upper = 0;
		for(int j = 0; j < matrix[0].length; j++) {
			upper += Math.min(1.0, max_xy[j] + error1) * Math.min(1.0, outputdist[j] + error2);
		}
		//System.out.println("  upper = " + upper);
		double MELMax = MinEntropy.minEntropy(pmf) + InfoTheory.log2(Math.min(upper, 1.0));
		//System.out.println("  MELMax = " + MELMax);
	
		// Calculate the estimate (for debug)
		/*
		double est = 0;
		for(int j = 0; j < matrix[0].length; j++) {
			est += max_xy[j] * outputdist[j];
		}
		est = minEntropy(pmf) + log2(est);
		System.out.println("  MELEst = " + est);
		*/
	
		double[] result = {MELMin, MELMax};
		return result;
	}


	////////////////////////////////////////////////////////////////////////////
	// Confidence interval for min-entropy leakage, based on Chi-square tests //
	
	// The minimum frequency that will not be merged
	public static final int threshold  = 5;


	/*
	 * Calculates the lower bound of the confidence interval of
	 * the estimated min-entropy leakage using the Chi-square test
	 * when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @param priorCountsMerged
	 * @param chiSquarePrior
	 * @return the lower bound of the confidence interval of
	 *         the estimated min-entropy leakage 
	 *         when the input distribution is also estimated.
	 */
	private static double minEntropyLeakLowerBoundConfidenceIntervalChiSquare(Observations obs, ArrayList<Integer> priorCountsMerged, double chiSquarePrior) {
		/* Calculate the (prior) input sample distribution that
		 gives the upper bound of the prior vulnerability */
		//Observations.printDist(od, "od");
		//Observations.printDist(priorCountsMerged, "priorCountsMerged");
		int[] odMax = MinEntropy.obsMaximizingVulnerability(priorCountsMerged, chiSquarePrior);
		if(odMax == null)  return Double.NaN;
		//Observations.printDist(odMax, "odMax");
		//double tmp2ChiSquare = Stats.chiSquare(od, odMax);
		//System.out.println("  tmp2ChiSquare = " + tmp2ChiSquare);
		double[] pmfMax = Observations.observationsToPMF(odMax);
	
		// Obtains the upper bound of the (posterior) conditional min-entropy leakage
		double condMELupper = MinEntropy.minConditionalEntropyUpperBoundConfidenceIntervalChiSquare(obs);
	
		// Calculate the lower bound of the confidence interval of the min-entropy leakage
		double lower = MinEntropy.minEntropy(pmfMax) - condMELupper;
		return Math.max(0.0, lower);
	}

	/**
	 * Calculates the lower bound of the confidence interval of
	 * the estimated min-entropy leakage using the Chi-square test
	 * when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @return the lower bound of the confidence interval of
	 *         the estimated min-entropy leakage 
	 *         when the input distribution is also estimated.
	 */
	public static double minEntropyLeakLowerBoundConfidenceIntervalChiSquare(Observations obs) {
		// Output a caution about the sample size
		if(InfoTheory.verbose >= 1 && !obs.hasSufficientSamplesForMEL()) {
			System.out.println("Caution: The sample size is not large enough to estimate the confidence interval.");
			if(InfoTheory.verbose >= 3)
				obs.printObservationsMatrix();
		}
		
		/* Calculate the list of observed counts (prior) in which
		   small counts are merged */
		int[] od = obs.getInputObservationsArray();
		ArrayList<Integer> priorCountsMerged = MinEntropy.mergedData(od, threshold);
		
		// Calculate the degree of freedom of the (prior) input sample distribution
		final int freedomPrior = MinEntropy.degreeOfFreedomPrior(priorCountsMerged);
		if(freedomPrior <= 0) {
			if(InfoTheory.verbose >= 1) {
				System.out.println("Error: Cannot estimate the confidence interval.");
				System.out.println("  The sample size is too small.");
			}
			return Double.NaN;
		}
	
		// Calculate the upper bound for the 95% confidence interval for the &chi;-squared distribution
		final double chiSquarePrior = Stats.chiSqu95Interval(freedomPrior);
		if(InfoTheory.verbose >= 5) {
			System.out.printf("  Degree of freedom (Prior)     = %3d", freedomPrior);
			//System.out.printf("  (noOfInputs = %3d)", noOfInputs);
			//System.out.println("                   ");
			System.out.println("  chi-square = " + chiSquarePrior);
		}
		// Return the lower bound of the confidence interlval
		return minEntropyLeakLowerBoundConfidenceIntervalChiSquare(obs, priorCountsMerged, chiSquarePrior);
	}

	/*
	 * Calculates the upper bound of the confidence interval of
	 * the estimated min-entropy leakage using the Chi-square test
	 * when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @param priorCountsMerged
	 * @param chiSquarePrior
	 * @return the upper bound of the confidence interval of
	 *         the estimated min-entropy leakage 
	 *         when the input distribution is also estimated.
	 */
	private static double minEntropyLeakUpperBoundConfidenceIntervalChiSquare(Observations obs, ArrayList<Integer> priorCountsMerged, double chiSquarePrior) {
		/* Calculate the (prior) input sample distribution that
		 gives the lower bound of the prior vulnerability */
		int[] odMin = MinEntropy.obsMinimizingVulnerability(priorCountsMerged, chiSquarePrior);
		if(odMin == null)  return Double.NaN;
		
		//Observations.printDist(odMin, "odMin");
		//double tmp3ChiSquare = Stats.chiSquare(od, odMin);
		//System.out.println("  tmp3ChiSquare = " + tmp3ChiSquare + "  desired: " + chiSquarePrior);
		double[] pmfMin = Observations.observationsToPMF(odMin);
	
		// Obtains the lower bound of the (posterior) conditional min-entropy leakage
		double condMELlower = MinEntropy.minConditionalEntropyLowerBoundConfidenceIntervalChiSquare(obs);
	
		// Calculate the upper bound of the confidence interval of the min-entropy leakage
		double upper = MinEntropy.minEntropy(pmfMin) - condMELlower;
		return upper;
	}

	/**
	 * Calculates the upper bound of the confidence interval of
	 * the estimated min-entropy leakage using the Chi-square test
	 * when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @return the upper bound of the confidence interval of
	 *         the estimated min-entropy leakage 
	 *         when the input distribution is also estimated.
	 */
	public static double minEntropyLeakUpperBoundConfidenceIntervalChiSquare(Observations obs) {
		// Output a caution about the sample size
		if(InfoTheory.verbose >= 1 && !obs.hasSufficientSamplesForMEL()) {
			System.out.println("Caution: The sample size is not large enough to estimate the confidence interval.");
			if(InfoTheory.verbose >= 3)
				obs.printObservationsMatrix();
		}
		
		/* Calculate the list of observed counts (prior) in which
		   small counts are merged */
		int[] od = obs.getInputObservationsArray();
		ArrayList<Integer> priorCountsMerged = MinEntropy.mergedData(od, threshold);
		
		// Calculate the degree of freedom of the (prior) input sample distribution
		final int freedomPrior = MinEntropy.degreeOfFreedomPrior(priorCountsMerged);
		if(freedomPrior <= 0) {
			if(InfoTheory.verbose >= 1) {
				System.out.println("Error: Cannot estimate the confidence interval.");
				System.out.println("  The sample size is too small.");
			}
			return Double.NaN;
		}
	
		// Calculate the upper bound for the 95% confidence interval for the &chi;-squared distribution
		final double chiSquarePrior = Stats.chiSqu95Interval(freedomPrior);
		if(InfoTheory.verbose >= 5) {
			System.out.printf("  Degree of freedom (Prior)     = %3d", freedomPrior);
			//System.out.printf("  (noOfInputs = %3d)", noOfInputs);
			//System.out.println("                   ");
			System.out.println("  chi-square = " + chiSquarePrior);
		}
		// Return the upper bound of the confidence interlval
		return minEntropyLeakUpperBoundConfidenceIntervalChiSquare(obs, priorCountsMerged, chiSquarePrior);
	}

	/**
	 * Calculates the confidence interval of the estimated min-entropy leakage
	 * using the Chi-square test when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @return the confidence interval of the estimated min-entropy leakage 
	 *         when the input distribution is also estimated.
	 */
	public static double[] minEntropyLeakConfidenceIntervalChiSquare(Observations obs) {
		// Output a caution about the sample size
		if(InfoTheory.verbose >= 1 && !obs.hasSufficientSamplesForMEL()) {
			System.out.println("Caution: The sample size is not large enough to estimate the confidence interval.");
			if(InfoTheory.verbose >= 3)
				obs.printObservationsMatrix();
		}
		
		/* Calculate the list of observed counts (prior) in which
		   small counts are merged */
		int[] od = obs.getInputObservationsArray();
		ArrayList<Integer> priorCountsMerged = MinEntropy.mergedData(od, threshold);
		
		/*
		for(Integer i : priorCountsMerged) {
			System.out.println("count = " + i + "  size = " + priorCountsMerged.size());
		}
		*/
		
		// Calculate the degree of freedom of the (prior) input sample distribution
		final int freedomPrior = MinEntropy.degreeOfFreedomPrior(priorCountsMerged);
		if(freedomPrior <= 0) {
			if(InfoTheory.verbose >= 1) {
				System.out.println("Error: Cannot estimate the confidence interval.");
				System.out.println("  The sample size is too small.");
			}
			double[] result = new double[2];
			result[0] = Double.NaN;
			result[1] = Double.NaN;
			return result;
		}
	
		// Calculate the upper bound for the 95% confidence interval for the &chi;-squared distribution
		final double chiSquarePrior = Stats.chiSqu95Interval(freedomPrior);
		if(InfoTheory.verbose >= 5) {
			System.out.printf("  Degree of freedom (Prior)     = %3d", freedomPrior);
			//System.out.printf("  (noOfInputs = %3d)", noOfInputs);
			//System.out.println("                   ");
			System.out.println("  chi-square = " + chiSquarePrior);
		}
		
		// Numbers of inputs and outputs
		int noOfInputs = obs.getUniqueInputCount();
		int noOfOutputs = obs.getUniqueOutputCount();
		
		/* Calculate the (prior) input sample distribution that
		 gives the upper bound of the prior vulnerability */
		//Observations.printDist(od, "od");
		//Observations.printDist(priorCountsMerged, "priorCountsMerged");
		int[] odMax = MinEntropy.obsMaximizingVulnerability(priorCountsMerged, chiSquarePrior);
		if(odMax == null) {
			double[] result = new double[2];
			result[0] = Double.NaN;
			result[1] = Double.NaN;
			return result;
		}
		//Observations.printDist(odMax, "odMax");
		//double tmp2ChiSquare = Stats.chiSquare(od, odMax);
		//System.out.println("  tmp2ChiSquare = " + tmp2ChiSquare);
		double[] pmfMax = Observations.observationsToPMF(odMax);
	
		/* Calculate the (prior) input sample distribution that
		 gives the lower bound of the prior vulnerability */
		int[] odMin = MinEntropy.obsMinimizingVulnerability(priorCountsMerged, chiSquarePrior);
		if(odMin == null) {
			double[] result = new double[2];
			result[0] = Double.NaN;
			result[1] = Double.NaN;
			return result;
		}
		//Observations.printDist(odMin, "odMin");
		//double tmp3ChiSquare = Stats.chiSquare(od, odMin);
		//System.out.println("  tmp3ChiSquare = " + tmp3ChiSquare + "  desired: " + chiSquarePrior);
		double[] pmfMin = Observations.observationsToPMF(odMin);
	
		/* Calculate the list of observed counts (posterior) in which
		   small counts are merged */
		int[][] jod = obs.getObservationsMatrix();
		ArrayList<ArrayList<Integer>> list = MinEntropy.mergedData(jod, threshold);
	
		// Calculate the degree of freedom (posterior)
		final int freedomPosterior = MinEntropy.degreeOfFreedomPosterior(list);
	
		// Calculate the upper bound for the 95% confidence interval for the &chi;-squared distribution
		final double chiSquarePosterior = Stats.chiSqu95Interval(freedomPosterior);
		if(InfoTheory.verbose >= 5) {
			System.out.printf("  Degree of freedom (Posterior) = %3d",  freedomPosterior);
			//System.out.printf("  (noOfInputs = %3d", noOfInputs);
			//System.out.printf(", noOfOutputs = %3d)", noOfOutputs);
			System.out.println("  chi-square = " + chiSquarePosterior);
		}
		
		/* Calculate the (posterior) joint sample distribution that
		   gives the upper bound of the posterior min-entropy */
		int[][] jodMax = MinEntropy.obsMaximizingCondVulnerability(list, chiSquarePosterior, noOfInputs, noOfOutputs);
		if(jodMax == null) {
			double[] result = new double[2];
			result[0] = Double.NaN;
			result[1] = Double.NaN;
			return result;
		}
		double[][] jpmfMax = Observations.observationsToJPMF(jodMax);
	
		/* Calculate the (posterior) joint sample distribution that
		   gives the lower bound of the posterior min-entropy */
		int[][] jodMin = MinEntropy.obsMinimizingCondVulnerability(list, chiSquarePosterior, noOfInputs, noOfOutputs);
		if(jodMin == null) {
			double[] result = new double[2];
			result[0] = Double.NaN;
			result[1] = Double.NaN;
			return result;
		}
		double[][] jpmfMin = Observations.observationsToJPMF(jodMin);
	
		// Calculate the confidence interval of the min-entropy leakage
		double lower = MinEntropy.minEntropy(pmfMax) + InfoTheory.log2(conditionalVulnerability(jpmfMin));
		double upper = MinEntropy.minEntropy(pmfMin) + InfoTheory.log2(conditionalVulnerability(jpmfMax));
		if(InfoTheory.verbose >= 5) {
			// Display the confidence interval of the min-entropy and conditional min-entropy, their chi-squares
			System.out.printf("  minEntropy =     [ %13.10f, %13.10f ] ", MinEntropy.minEntropy(pmfMax), MinEntropy.minEntropy(pmfMin));
			System.out.printf("  Chi-square: ( %6.3f, %6.3f )\n", Stats.chiSquare(od, odMax), Stats.chiSquare(od, odMin));
			System.out.printf("  condMinEntropy = [ %13.10f, %13.10f ] ", (-InfoTheory.log2(conditionalVulnerability(jpmfMax))), (-InfoTheory.log2(conditionalVulnerability(jpmfMin))));
			System.out.printf("  Chi-square: ( %6.3f, %6.3f )\n", MinEntropy.chiSquare(MinEntropy.listToMatrix(list, noOfInputs, noOfOutputs), jodMax), MinEntropy.chiSquare(MinEntropy.listToMatrix(list, noOfInputs, noOfOutputs), jodMin));
		}
		
		double result[] = new double[2];
		result[0] = Math.max(0.0, lower);
		result[1] = upper;
		return result;
	}

	/*
	 * Calculates the lower bound of the confidence interval of
	 * the estimated conditional min-entropy using the Chi-square
	 * test when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @param list
	 * @param chiSquarePosterior
	 * @return the lower bound of the confidence interval of
	 *         the estimated conditional min-entropy  
	 *         when the input distribution is also estimated.
	 */
	private static double minConditionalEntropyLowerBoundConfidenceIntervalChiSquare(Observations obs, ArrayList<ArrayList<Integer>> list, double chiSquarePosterior) {
		// Numbers of inputs and outputs
		int noOfInputs = obs.getUniqueInputCount();
		int noOfOutputs = obs.getUniqueOutputCount();
		
		/* Calculate the (posterior) joint sample distribution that
		   gives the upper bound of the posterior min-entropy */
		int[][] jodMax = MinEntropy.obsMaximizingCondVulnerability(list, chiSquarePosterior, noOfInputs, noOfOutputs);
		if(jodMax == null) return Double.NaN;
		double[][] jpmfMax = Observations.observationsToJPMF(jodMax);
	
		// Calculate the lower bound of the confidence interval of the conditional min-entropy
		double lower = -InfoTheory.log2(conditionalVulnerability(jpmfMax));
		if(InfoTheory.verbose >= 5) {
			// Display the confidence interval of the conditional min-entropy, their chi-squares
			System.out.printf("  condMinEntropy <= %13.10f", (-InfoTheory.log2(conditionalVulnerability(jpmfMax))));
			System.out.printf("  Chi-square: %6.3f\n", MinEntropy.chiSquare(MinEntropy.listToMatrix(list, noOfInputs, noOfOutputs), jodMax));
			//System.out.printf("  (noOfInputs = %3d", noOfInputs);
			//System.out.printf(", noOfOutputs = %3d)", noOfOutputs);
		}
		return Math.max(0.0, lower);
	}

	/**
	 * Calculates the lower bound of the confidence interval of
	 * the estimated conditional min-entropy using the Chi-square
	 * test when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @return the lower bound of the confidence interval of
	 *         the estimated conditional min-entropy  
	 *         when the input distribution is also estimated.
	 */
	public static double minConditionalEntropyLowerBoundConfidenceIntervalChiSquare(Observations obs) {
		// Output a caution about the sample size
		if(InfoTheory.verbose >= 1 && !obs.hasSufficientSamplesForMEL()) {
			System.out.println("Caution: The sample size is not large enough to estimate the confidence interval.");
			if(InfoTheory.verbose >= 3)
				obs.printObservationsMatrix();
		}
		
		/* Calculate the list of observed counts (posterior) in which
		   small counts are merged */
		int[][] jod = obs.getObservationsMatrix();
		ArrayList<ArrayList<Integer>> list = MinEntropy.mergedData(jod, threshold);
	
		// Calculate the degree of freedom (posterior)
		final int freedomPosterior = MinEntropy.degreeOfFreedomPosterior(list);
	
		// Calculate the upper bound for the 95% confidence interval for the &chi;-squared distribution
		final double chiSquarePosterior = Stats.chiSqu95Interval(freedomPosterior);
		if(InfoTheory.verbose >= 5) {
			System.out.printf("  Degree of freedom (Posterior) = %3d",  freedomPosterior);
			System.out.println("  chi-square = " + chiSquarePosterior);
		}
		
		// Possible maximum of the conditional min-entropy is min-entropy of the prior
		double maximum = minEntropy(obs.getInputProbDist());
	
		// Return the lower bound of the confidence interlval
		return Math.min(maximum, minConditionalEntropyLowerBoundConfidenceIntervalChiSquare(obs, list, chiSquarePosterior));
	}

	/*
	 * Calculates the upper bound of the confidence interval of
	 * the estimated conditional min-entropy using the Chi-square
	 * test when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @param list
	 * @param chiSquarePosterior
	 * @return the upper bound of the confidence interval of
	 *         the estimated conditional min-entropy  
	 *         when the input distribution is also estimated.
	 */
	private static double minConditionalEntropyUpperBoundConfidenceIntervalChiSquare(Observations obs, ArrayList<ArrayList<Integer>> list, double chiSquarePosterior) {
		// Numbers of inputs and outputs
		int noOfInputs = obs.getUniqueInputCount();
		int noOfOutputs = obs.getUniqueOutputCount();
		
		/* Calculate the (posterior) joint sample distribution that
		   gives the upper bound of the posterior min-entropy */
		int[][] jodMin = MinEntropy.obsMinimizingCondVulnerability(list, chiSquarePosterior, noOfInputs, noOfOutputs);
		if(jodMin == null) return Double.NaN;
		double[][] jpmfMin = Observations.observationsToJPMF(jodMin);
	
		// Calculate the upper bound of the confidence interval of the conditional min-entropy
		double upper = -InfoTheory.log2(conditionalVulnerability(jpmfMin));
		if(InfoTheory.verbose >= 5) {
			// Display the confidence interval of the conditional min-entropy, their chi-squares
			System.out.printf("  condMinEntropy <= %13.10f ", (-InfoTheory.log2(conditionalVulnerability(jpmfMin))));
			System.out.printf("  Chi-square: %6.3f\n", MinEntropy.chiSquare(MinEntropy.listToMatrix(list, noOfInputs, noOfOutputs), jodMin));
			//System.out.printf("  (noOfInputs = %3d", noOfInputs);
			//System.out.printf(", noOfOutputs = %3d)", noOfOutputs);
		}
		return Math.max(0.0, upper);
	}

	/**
	 * Calculates the upper bound of the confidence interval of
	 * the estimated conditional min-entropy using the Chi-square
	 * test when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @return the upper bound of the confidence interval of
	 *         the estimated conditional min-entropy  
	 *         when the input distribution is also estimated.
	 */
	public static double minConditionalEntropyUpperBoundConfidenceIntervalChiSquare(Observations obs) {
		// Output a caution about the sample size
		if(InfoTheory.verbose >= 1 && !obs.hasSufficientSamplesForMEL()) {
			System.out.println("Caution: The sample size is not large enough to estimate the confidence interval.");
			if(InfoTheory.verbose >= 3)
				obs.printObservationsMatrix();
		}
		
		/* Calculate the list of observed counts (posterior) in which
		   small counts are merged */
		int[][] jod = obs.getObservationsMatrix();
		ArrayList<ArrayList<Integer>> list = MinEntropy.mergedData(jod, threshold);
	
		// Calculate the degree of freedom (posterior)
		final int freedomPosterior = MinEntropy.degreeOfFreedomPosterior(list);
	
		// Calculate the upper bound for the 95% confidence interval for the &chi;-squared distribution
		final double chiSquarePosterior = Stats.chiSqu95Interval(freedomPosterior);
		if(InfoTheory.verbose >= 5) {
			System.out.printf("  Degree of freedom (Posterior) = %3d",  freedomPosterior);
			System.out.println("  chi-square = " + chiSquarePosterior);
		}
	
		// Return the upper bound of the confidence interlval
		return minConditionalEntropyUpperBoundConfidenceIntervalChiSquare(obs, list, chiSquarePosterior);
	}

	/**
	 * Calculates the confidence interval of the estimated conditional min-entropy 
	 * using the Chi-square test when the input distribution is also estimated.
	 * 
	 * @param obs observations
	 * @return the confidence interval of the estimated conditional min-entropy  
	 *         when the input distribution is also estimated.
	 */
	public static double[] minConditionalEntropyConfidenceIntervalChiSquare(Observations obs) {
		// Output a caution about the sample size
		if(InfoTheory.verbose >= 1 && !obs.hasSufficientSamplesForMEL()) {
			System.out.println("Caution: The sample size is not large enough to estimate the confidence interval.");
			if(InfoTheory.verbose >= 3)
				obs.printObservationsMatrix();
		}
		
		/* Calculate the list of observed counts (posterior) in which
		   small counts are merged */
		int[][] jod = obs.getObservationsMatrix();
		ArrayList<ArrayList<Integer>> list = MinEntropy.mergedData(jod, threshold);
	
		// Calculate the degree of freedom (posterior)
		final int freedomPosterior = MinEntropy.degreeOfFreedomPosterior(list);
	
		// Calculate the upper bound for the 95% confidence interval for the &chi;-squared distribution
		final double chiSquarePosterior = Stats.chiSqu95Interval(freedomPosterior);
		if(InfoTheory.verbose >= 5) {
			System.out.printf("  Degree of freedom (Posterior) = %3d",  freedomPosterior);
			System.out.println("  chi-square = " + chiSquarePosterior);
		}
		
		// Calculate the confidence interval of the conditional min-entropy
		double lower = minConditionalEntropyLowerBoundConfidenceIntervalChiSquare(obs, list, chiSquarePosterior);
		double upper = minConditionalEntropyUpperBoundConfidenceIntervalChiSquare(obs, list, chiSquarePosterior);
		if(InfoTheory.verbose >= 5) {
			// Display the confidence interval of the conditional min-entropy, their chi-squares
			System.out.printf("  condMinEntropy = [ %13.10f, %13.10f ] ", lower, upper);
			//System.out.printf("  (noOfInputs = %3d", noOfInputs);
			//System.out.printf(", noOfOutputs = %3d)", noOfOutputs);
		}
		
		double result[] = new double[2];
		result[0] = Math.max(0.0, lower);
		result[1] = upper;
		return result;
	}

	/**
	 * Tests whether the sample size recorded in this Observations object
	 * is sufficient for estimating min-entropy leakage.
	 * We require that no more than 20% of the non-zero expected frequencies
	 * are below 5.
	 * 
	 * @param obs observations
	 * @param numCells the number of unique pairs of input and output
	 * @return <tt>true</tt> if enough samples have been collected to allow an
	 * accurate estimation of min-entropy leakage to be calculated;
	 * <tt>false</tt> if not.
	 */
	public static boolean hasSufficientSamplesForMEL(Observations obs, int numCells) {
		/* When the sample size is relatively large, we check whether
		   no more than 20% of the non-zero observed frequencies are below 5. */
		int noOfInputs = obs.getUniqueInputCount();
		int noOfOutputs = obs.getUniqueOutputCount();
		int countSmallFrequencies = 0;
		ArrayList<ArrayList<Integer>> list = MinEntropy.mergedData(obs.getObservationsMatrix(), 0);
		final double chiSquarePosterior = Stats.chiSqu95Interval(MinEntropy.degreeOfFreedomPosterior(list));
		int[][] jodMin = MinEntropy.obsMinimizingCondVulnerability(list, chiSquarePosterior, noOfInputs, noOfOutputs);
		for(int numRow = 0; numRow < jodMin.length; numRow++) {
			for(int numCol = 0; numCol < jodMin[0].length; numCol++) {
				if(jodMin[numRow][numCol] != 0 && jodMin[numRow][numCol] < threshold) {
					countSmallFrequencies++;
				}
				if((double)countSmallFrequencies > (double)numCells * 0.2) {
					return false;
				}
			}
		}
		return true;
	}


	// The maximum number of iteration when computing arrays of expected counts
	private final static int maxNumIterate = 1000;

	// The accuracy of &chi;-square values
	private final static double accuracy = 0.05;


	/*
	 * Converts an array list of observed counts to observations matrix. 
	 * @param list array list of oberved counts
	 * @param noOfInputs the number of inputs
	 * @param noOfOutputs the number of outputs
	 * @return observations matrix 
	 */
	private static int[][] listToMatrix(ArrayList<ArrayList<Integer>> list, int noOfInputs, int noOfOutputs) {
		int[][] matrix = new int[noOfInputs][noOfOutputs];
		for(int numCol = 0; numCol < noOfOutputs; numCol++) {
			for(int numRow = 0; numRow < noOfInputs; numRow++) {
				if(numCol < list.size() && numRow < list.get(numCol).size()) {
					matrix[numRow][numCol] = list.get(numCol).get(numRow);
				} else {
					matrix[numRow][numCol] = 0;
				}
			}
		}
		return matrix;
	}

	/*
	 * Returns &chi;-square value given observed counts and expected counts.
	 * 
	 * @param observedCounts matrix of observed counts 
	 * @param expectedCounts matrix of expected counts
	 * @return &chi;-square value
	 */
	private static double chiSquare(int[][] observedCounts, int[][] expectedCounts) {
		if(observedCounts.length != expectedCounts.length ||
		   observedCounts[0].length != expectedCounts[0].length) {
			if(InfoTheory.verbose >= 1) {
				System.out.println("Error: The lengths of observed and expected counts are different.");
			}
			return Double.NaN;
		}
		int size = observedCounts.length * observedCounts[0].length;
		ArrayList<Integer> observedCountsArrayList = new ArrayList<Integer>();
		ArrayList<Integer> expectedCountsArrayList = new ArrayList<Integer>();
		int index = 0;
		for(int numRow = 0; numRow < observedCounts.length; numRow++) {
			for(int numCol = 0; numCol < observedCounts[0].length; numCol++) {
				if(observedCounts[numRow][numCol] != 0 && expectedCounts[numRow][numCol] != 0) {
					observedCountsArrayList.add(observedCounts[numRow][numCol]);
					expectedCountsArrayList.add(expectedCounts[numRow][numCol]);
					index++;
				}
			}
		}
		int[] observedCountsArray = new int[index];
		int[] expectedCountsArray = new int[index];
		if(InfoTheory.verbose >= 7) {
			System.out.println("  ------------------------------");
			System.out.println("  ObservedCounts, ExpectedCounts");
		}
		for(int i = 0; i < index; i++) {
			observedCountsArray[i] = observedCountsArrayList.get(i);
			expectedCountsArray[i] = expectedCountsArrayList.get(i);
			if(InfoTheory.verbose >= 7) {
				System.out.println("  " + observedCountsArray[i] + ", " + expectedCountsArray[i]);
			}
		}
		if(InfoTheory.verbose >= 7) {
			System.out.println("  ------------------------------");
		}
		double chiSq = Stats.chiSquare(observedCountsArray, expectedCountsArray);
		return chiSq;
	}

	/*
	 * Returns the degree of freedom given data.
	 * @param list array of observation counts
	 * @return the degree of freedom of list
	 */
	private static int degreeOfFreedomPrior(ArrayList<Integer> column) {
		return column.size() - 1;
	}

	/*
	 * Returns the degree of freedom given data.
	 * @param list list of columns of an observation matrix
	 * @return the degree of freedom of list
	 */
	private static int degreeOfFreedomPosterior(ArrayList<ArrayList<Integer>> list) {
		int freedom = 0;
		for(ArrayList<Integer> column : list) {
			freedom += column.size();
		}
		return freedom - 1;
	}

	/*
	 * Merges small observed counts in a given observation matrix.
	 * 
	 * @param jod observations matrix
	 * @param threshold the minimum frequency that will not be merged
	 * @return observations matrix in which small observed counts are merged
	 */
	private static ArrayList<ArrayList<Integer>> mergedData(int[][] jod, int threshold) {
		final int noOfInputs = jod.length;
		final int noOfOutputs = jod[0].length;
		ArrayList<ArrayList<Integer>> list = new ArrayList<ArrayList<Integer>>();
		for(int numCol = 0; numCol < noOfOutputs; numCol++) {
			int[] column = new int[noOfInputs];
			for(int numRow = 0; numRow < noOfInputs; numRow++) {
				column[numRow] = jod[numRow][numCol];
			}
			ArrayList<Integer> columnModified = MinEntropy.mergedData(column, threshold);
			list.add(columnModified);
		}
		return list;
	}

	/*
	 * Returns a list of observed counts in which small counts are merged.
	 * @param od array of observed counts
	 * @param threshold the minimum frequency that will not be merged
	 * @return list of observed counts in which small counts are merged
	 */
	private static ArrayList<Integer> mergedData(int[] od, int threshold) {
		if(threshold <= 0)  threshold = 1;
		int size = od.length;
		ArrayList<Integer> column = new ArrayList<Integer>();
		int minimum = 0;
		int numRowMin = 0;
		int mergedValue = 0;
		for(int numRow = 0; numRow < size; numRow++) {
			//System.out.println("MinEnt:1065:  od[" + numRow + "] = " + od[numRow] + "  mergedValue = " + mergedValue);
			if(od[numRow] < threshold) {
				mergedValue += od[numRow];
			} else if(minimum == 0) {
				minimum = od[numRow];
				numRowMin = numRow;
			} else if(od[numRow] < minimum) {
				minimum = od[numRow];
				numRowMin = numRow;
			}
		}
		for(int numRow = 0; numRow < size; numRow++) {
			if(od[numRow] >= threshold) {
				if(numRow == numRowMin && mergedValue < threshold) {
					column.add(od[numRow] + mergedValue);
				} else {
					column.add(od[numRow]);
				}
			}
		}
		if(mergedValue >= threshold) {
			column.add(mergedValue);
		}
		return column;
	}

	/*
	 * Returns an array of expected counts that maximizes the vulnerability.
	 * 
	 * @param priorCounts array of observed counts
	 * @param chiSquare &chi;-square value
	 * @return array of expected counts that maximizes the vulnerability
	 */
	private static int[] obsMaximizingVulnerability(ArrayList<Integer> priorCounts, final double chiSquare) {
		// Size of the arrray list priorCounts
		int size = priorCounts.size();
		if(size <= 0) {
			if(InfoTheory.verbose >= 1) {
				System.out.println("Error: Cannot estimate the confidence interval.");
				System.out.println("  The sample size is too small.");
			}
			return null;
		}
		
		// Convert arrayList to array
		int[] od = new int[size];
		for(int i = 0; i < size; i ++) {
			od[i] = priorCounts.get(i);
		}
		
		// Maximum count in od
		int maxIndex = Stats.maxIndex(od);
		//System.out.println("  maxIndex = " + maxIndex);
		int maxCount = od[maxIndex];
	
		// Modified probability distribution
		int[] odMax = new int[size];
		
		// In case size == 1
		if(size == 1) {
			odMax[0] = priorCounts.get(0);
			for(int i = 1; i < size; i++) {
				odMax[i] = 0;
			}
			return odMax;
		}
		
		// Sort od and obtain its sort indeces
		ArrayList<Pair<Integer,Integer>> odIndexed = new ArrayList<Pair<Integer,Integer>>();
		for(int i = 0; i < size; i++) {
			Pair<Integer,Integer> p = new Pair<Integer,Integer>(od[i], i);
			odIndexed.add(p);
		}
	    ComparatorIntegers comparator = new ComparatorIntegers();
		Collections.sort(odIndexed, comparator);
		
		// Initialize
		int countAdded = (int)Math.sqrt(chiSquare / (double)size * (double)maxCount);
		int sumOfOthers = 0;
		for(int i = 0; i < size; i++) {
			if(i != maxIndex)
				sumOfOthers += Math.max(threshold, od[i]);
		}
		if(countAdded > sumOfOthers) {
			countAdded = sumOfOthers;
		}
		odMax[maxIndex] = od[maxIndex] + countAdded;
		//System.out.println("  maxIndex = " + maxIndex + "  countAdded = " + countAdded);
		int countSubtracted = countAdded;
		for(int i = 0; i < size; i++) {
			int index = odIndexed.get(i).getElement2();
			if(index != maxIndex) {
				if(od[index] > 0) {
					if(od[index] < threshold) {
						odMax[index] = threshold;
					} else {
						odMax[index] = Math.max(threshold, od[index] - countSubtracted / Math.max(1, size - i - 1));
						//System.out.print("  od[" + i + "] = " + od[i]);
						//System.out.print("  countSubtracted = " + countSubtracted);
						//System.out.println("  size = " + size);
						countSubtracted -= (od[index] - odMax[index]); 
					}
				} else {
					odMax[i] = 0;
				}
			}
			//System.out.println("  odMax[" + i + "] = " + odMax[i]);
		}
		//Observations.printDist(odMax, "odMax @MinEnt:1173");
	
		// Iteration
		double tmpChiSquare = Stats.chiSquare(od, odMax);
		int numIterate = 0;
		do {
			if(tmpChiSquare > chiSquare && countAdded >= 1) {
				//System.out.println("  MinEnt:1180 tmpChiSquare = " + tmpChiSquare + " chiSquare = " + chiSquare + "  (-) countAdded = " + countAdded);
				countAdded--;
				if(tmpChiSquare - chiSquare > 10 && countAdded > 40)  // for faster convvergence
					countAdded -= 30;
			} else {
				//System.out.println("  MinEnt:1185 tmpChiSquare = " + tmpChiSquare + "  (+) countAdded = " + countAdded);
				countAdded++;
				if(chiSquare - tmpChiSquare > 10)  // for faster convvergence
					countAdded += 30;
			}
			// update odMax according to the new countAdded
			odMax[maxIndex] = od[maxIndex] + countAdded;
			countSubtracted = countAdded;
			for(int i = 0; i < size; i++) {
				int index = odIndexed.get(i).getElement2();
				if(index != maxIndex) {
					if(od[index] > 0) {
						if(od[index] < threshold) {
							odMax[index] = threshold;
						} else {
							odMax[index] = Math.max(threshold, od[index] - countSubtracted / Math.max(1, size - i - 1));
							//System.out.print("  od[" + i + "] = " + od[i]);
							//System.out.print("  countAdded = " + countSubtracted);
							//System.out.println("  size = " + size);
							countSubtracted -= (od[index] - odMax[index]); 
						}
					} else {
						odMax[i] = 0;
					}
				}
			}
			numIterate++;
			tmpChiSquare = Stats.chiSquare(od, odMax);
			//Observations.printDist(odMax, "odMax @MinEnt:1213  tmpChiSquare = " + tmpChiSquare);
		} while(Math.abs(tmpChiSquare - chiSquare) > accuracy && numIterate < maxNumIterate && countAdded > 0);
		if(InfoTheory.verbose >= 5) {
			/*
			System.out.println("  Chi-square " + tmpChiSquare + "  is used after iterating " + numIterate + " times.");
			System.out.println("  Desired Chi-square was " + chiSquare + ".");
			Observations.printDist(od, "Original counts (od) was:");
			Observations.printDist(odMax, "Modified counts (odMax) was:");
			System.out.println("  ----------");
			*/
		}
		return odMax;
	}

	/*
	 * Retunrns a uniform array with the same sum.
	 * 
	 * @param array array of integers
	 * @return uniform array with the same sum
	 */
	private static int[] uniformFrequenciesArray(int[] array) {
		// sum
		int sum = 0;
		for(int freq : array) {
			sum += freq;
		}
		int mean = sum / array.length;
		int remained = sum - mean * array.length;
		int[] uniformFrequencies = new int[array.length];
		for(int i = 0; i < array.length; i++) {
			uniformFrequencies[i] = mean;
			if(i < remained) {
				uniformFrequencies[i]++;
			}
		}
		return uniformFrequencies;
	}

	/*
	 * Returns an array of expected counts that minimizes the vulnerability.
	 * 
	 * @param priorCounts array of observed counts
	 * @param chiSquare &chi;-square value
	 * @return array of expected counts that minimizes the vulnerability
	 */
	private static int[] obsMinimizingVulnerability(ArrayList<Integer> priorCounts, double chiSquare) {
		// Size of the arrray list priorCounts
		int size = priorCounts.size();
		if(size <= 0) {
			if(InfoTheory.verbose >= 1) {
				System.out.println("Error: Cannot estimate the confidence interval.");
				System.out.println("  The sample size is too small.");
			}
			return null;
		}
		
		// Convert arrayList to array
		int[] od = new int[size];
		int average = 0;
		for(int i = 0; i < size; i ++) {
			od[i] = priorCounts.get(i);
			//System.out.println(" od[" + i + "] = " + od[i]);
			average += od[i];
		}
		average = average / size - 1;
		
		// Maximum count in od
		int maxIndex = Stats.maxIndex(od);
		int maxCount = od[maxIndex];
		//System.out.println("maxIndex = " + maxIndex);
		//System.out.println("maxCount = " + maxCount);
		
		// ChiSquare with the uniform distribution (odMin should not be changed beyond uniform distribution)
		chiSquare = Math.min(chiSquare, Stats.chiSquare(od, uniformFrequenciesArray(od)));
		
		// Modified probability distribution
		int[] odMin = new int[size];
	
		// In case size == 1
		if(size == 1) {
			odMin[0] = priorCounts.get(0);
			for(int i = 1; i < size; i++) {
				odMin[i] = 0;
			}
			return odMin;
		}
		
		// Sort od and obtain its sort indeces
		ArrayList<Pair<Integer,Integer>> odIndexed = new ArrayList<Pair<Integer,Integer>>();
		for(int i = 0; i < size; i++) {
			Pair<Integer,Integer> p = new Pair<Integer,Integer>(od[i], i);
			odIndexed.add(p);
		}
	    ComparatorIntegers comparator = new ComparatorIntegers();
		Collections.sort(odIndexed, comparator);
		
		// Initialize
		double tmp = chiSquare / (double)size;
		//int countSubtracted = (int)Math.sqrt(chiSquare / (double)size * (double)maxCount);
		int countSubtracted = (int)(Math.sqrt(tmp * tmp + 4.0 * tmp * (double)maxCount) - tmp / 2.0);
		countSubtracted = Math.min(countSubtracted, (maxCount - average)); // Not to subtract too much
		
		int AdjustedCounts = countSubtracted;
		int IncreaseCounts = AdjustedCounts;
		int DecreaseCounts = AdjustedCounts;
		
		// Iteration
		double tmpChiSquare = 0.0;
		int numIterate = 0;
		do {
			// Initialize odMin
			for(int i = 0; i < size; i++) {
				odMin[i] = od[i];
			}
			//System.out.println("MinEnt:1327  Start... IncreaseCounts = " + IncreaseCounts);
			
			// increase counts to small expected counts
			for(int i = 0; i < size - 1; i++) {
				if(IncreaseCounts > 0) {
					int index1 = odIndexed.get(0).getElement2();
					int index2 = odIndexed.get(i+1).getElement2();
					if(IncreaseCounts >= (odMin[index2] - odMin[index1]) * (i + 1)) {
						IncreaseCounts = IncreaseCounts - (odMin[index2] - odMin[index1]) * (i + 1);
						for(int j = 0; j <= i; j++) {
							int index = odIndexed.get(j).getElement2();
							odMin[index] = odMin[index2];
						}
					} else {
						int sumAdded = 0;
						for(int j = 0; j <= i; j++) {
							int index = odIndexed.get(j).getElement2();
							int added = IncreaseCounts / (i + 1);
							sumAdded += added;
							odMin[index] += added;
						}
						int index = odIndexed.get(i).getElement2();
						odMin[index] += (IncreaseCounts - sumAdded);
						IncreaseCounts = 0;
					}
				}
			}
	
			
			//Observations.printDist(od, "MinEnt:1325 (od)");
			//Observations.printDist(odMin, "MinEnt:1326 (odMin)");
			
			// Decrease counts to small expected counts
			for(int i = size - 1; i > 0; i--) {
				if(DecreaseCounts > 0) {
					int index1 = odIndexed.get(size-1).getElement2();
					int index2 = odIndexed.get(i-1).getElement2();
					//System.out.println("MinEnt:1364  index1 = " + index1 + "  index2 = " + index2);
					//System.out.println("MinEnt:1365  odMin[index1] = " + odMin[index1] + "  odMin[index2] = " + odMin[index2]);
	
					if(DecreaseCounts >= (od[index1] - od[index2]) * (size - i)) {
						//System.out.println("MinEnt:1368  DecreaseCounts = " + DecreaseCounts + "  (od[index2] - od[index1]) = " + (od[index2] - od[index1]) + "  (size - i) = " + (size - i));
						for(int j = size - 1; j >= i; j--) {
							//System.out.println("MinEnt:1370  j = " + j + "  size = " + size + "  od[" + j + "] = " + od[j]);
							int index = odIndexed.get(j).getElement2();
							odMin[index] = od[index2];
						}
						DecreaseCounts = DecreaseCounts - (od[index1] - od[index2] * (size - i));
					} else {
						int sumSubtracted = 0;
						for(int j = size - 1; j >= i; j--) {
							int index = odIndexed.get(j).getElement2();
							int subtracted = DecreaseCounts / (size - i);
							sumSubtracted += subtracted;
							odMin[index] -= subtracted;
						}
						int index = odIndexed.get(i).getElement2();
						odMin[index] -= (DecreaseCounts - sumSubtracted);
						DecreaseCounts = 0;
					}
				}
			}
	
			// Update IncreaseCounts and DecreaseCounts
			//Observations.printDist(odMin, "MinEnt:1360 (odMin)");
			tmpChiSquare = Stats.chiSquare(od, odMin);
			if(tmpChiSquare > chiSquare) {
				//System.out.println("MinEnt:1363  chi-square = " + tmpChiSquare + "  desired = " + chiSquare);
				AdjustedCounts--;
				if(tmpChiSquare - chiSquare > 10 && IncreaseCounts > 40)  // for faster convvergence
					IncreaseCounts -= 30;
			} else {
				//System.out.println("MinEnt:1399  chi-square = " + tmpChiSquare + "  desired = " + chiSquare);
				AdjustedCounts++;
				if(chiSquare - tmpChiSquare > 10)  // for faster convvergence
					IncreaseCounts += 30;
			}
			//System.out.println("MinEnt:1404  IncreaseCounts = " + IncreaseCounts);
			IncreaseCounts = AdjustedCounts;
			DecreaseCounts = AdjustedCounts;
			
			numIterate++;
		} while(Math.abs(tmpChiSquare - chiSquare) > accuracy && numIterate < maxNumIterate && IncreaseCounts > 0);
		if(InfoTheory.verbose >= 5) {
			/*
			System.out.println("  Chi-square " + tmpChiSquare + "  is used after iterating " + numIterate + " times.");
			System.out.println("  Desired Chi-square was " + chiSquare + ".");
			Observations.printDist(od, "Original counts (od) was:");
			Observations.printDist(odMin, "Modified counts (odMin) was:");
			System.out.println("  ----------");
			*/
		}
		
		return odMin;
	}

	/*
	 * Returns a matrix of expected counts that maximizes the conditional vulnerability.
	 * 
	 * @param posteriorCounts array of observed counts
	 * @param chiSquare &chi;-square value
	 * @param noOfInputs the number of unique inputs
	 * @param noOfOutputs the number of unique outputs
	 * @return matrix of expected counts that maximizes the conditional vulnerability
	 */
	private static int[][] obsMaximizingCondVulnerability(ArrayList<ArrayList<Integer>> posteriorCounts, double chiSquare, int noOfInputs, int noOfOutputs) {
		int[][] obsMatrixMax = new int[noOfInputs][noOfOutputs];
		double sumChiSquare = 0.0;
		for(int numCol = 0; numCol < noOfOutputs; numCol++) {
			ArrayList<Integer> column = new ArrayList<Integer>();
			for(int numRow = 0; numRow < noOfInputs; numRow++) {
				if(numCol < posteriorCounts.size() && numRow < posteriorCounts.get(numCol).size()) {
					int expectedCounts = posteriorCounts.get(numCol).get(numRow);
					column.add(expectedCounts);
				}
			}
			
			// Calculate array of expected counts
			int[] columnModifed = obsMaximizingVulnerability(column, 1.5*(chiSquare - sumChiSquare)/(double)(noOfOutputs - numCol));
			if(columnModifed == null)  return null;
			//System.out.println("MinEnt:1447  chiSquare = " + chiSquare + " => " + sumChiSquare);
			
			// Calculate array of expected counts
			int[] columnObserved = new int[column.size()];
			for(int numRow = 0; numRow < column.size(); numRow++) {
				columnObserved[numRow] = column.get(numRow);
			}
			sumChiSquare += Stats.chiSquare(columnObserved, columnModifed);
			
			// Generate observations matrix
			for(int numRow = 0; numRow < noOfInputs; numRow++) {
				if(numRow < column.size()) {
					obsMatrixMax[numRow][numCol] = columnModifed[numRow];
				} else {
					obsMatrixMax[numRow][numCol] = 0;
				}
			}
		}
		return obsMatrixMax;
	}

	/*
	 * Returns a matrix of expected counts that minimizes the conditional vulnerability.
	 * 
	 * @param posteriorCounts array of observed counts
	 * @param chiSquare &chi;-square value
	 * @param noOfInputs the number of unique inputs
	 * @param noOfOutputs the number of unique outputs
	 * @return matrix of expected counts that minimizes the conditional vulnerability
	 */
	private static int[][] obsMinimizingCondVulnerability(ArrayList<ArrayList<Integer>> posteriorCounts, double chiSquare, int noOfInputs, int noOfOutputs) {
		int[][] obsMatrixMin = new int[noOfInputs][noOfOutputs];
		double sumChiSquare = 0.0;
		for(int numCol = 0; numCol < noOfOutputs; numCol++) {
			ArrayList<Integer> column = new ArrayList<Integer>();
			for(int numRow = 0; numRow < noOfInputs; numRow++) {
				if(numCol < posteriorCounts.size() && numRow < posteriorCounts.get(numCol).size()) {
					int expectedCounts = posteriorCounts.get(numCol).get(numRow);
					column.add(expectedCounts);
				}
			}
			// Calculate array of expected counts
			int[] columnModifed = obsMinimizingVulnerability(column, 1.5*(chiSquare - sumChiSquare)/(double)(noOfOutputs - numCol));
			if(columnModifed == null)  return null;
			
			// Calculate array of expected counts
			int[] columnObserved = new int[column.size()];
			for(int numRow = 0; numRow < column.size(); numRow++) {
				columnObserved[numRow] = column.get(numRow);
			}
			sumChiSquare += Stats.chiSquare(columnObserved, columnModifed);
			
			// Generate observations matrix
			for(int numRow = 0; numRow < noOfInputs; numRow++) {
				if(numRow < column.size()) {
					obsMatrixMin[numRow][numCol] = columnModifed[numRow];
				} else {
					obsMatrixMin[numRow][numCol] = 0;
				}
			}
		}
		return obsMatrixMin;
	}

	/**
	 * Calculates the min-capacity of a channel.
	 * <BR>
	 * min-capacity(W) = log( &Sigma;_y max_x W[x,y] )
	 * 
	 * @param matrix channel matrix array
	 * @return the min-capacity of matrix
	 * @deprecated This method should be replaced with another method {@link #minCapacity(Channel)}
	 */
	public static double minCapacity(double[][] matrix) {
		double sum = 0;
		for(int y = 0; y < (matrix[0]).length; y++) {
			double maxProb = 0;
			for(int x = 0; x < matrix.length; x++) {
				maxProb = Math.max(matrix[x][y], maxProb);
			}
			sum += maxProb;
		}
		return InfoTheory.log(sum, InfoTheory.base_log);
	}


	/////////////////////////////////////////////////////////////////////////////////
	// Confidence interval for min-entropy Leakage, based on binomial distribution //
	/*
	 * Calculates the lower bound of the confidence interval of
	 * the estimated min-entropy leakage using the binomial 
	 * distribution method.
	 * 
	 * @param pmf pmf array
	 * @param matrix channel matrix
	 * @param sampleSizeGivenInput the numbers of samples with given inputs
	 * @return the maximum possible error of the estimated min-entropy leakage 
	 */
	/*
	public static double minEntropyLeakLowerBoundBinomial(double[] pmf, double[][] matrix, int[] sampleSizeGivenInput) {
		// Confidence level
		final double minConfidenceLevel = 0.95;
		final double minConfidenceLevelOneSide = minConfidenceLevel + (1 - minConfidenceLevel)/2.0;
		//System.out.println("Minimum confidence level: " + minConfidenceLevel);
		//System.out.println("Minimum confidence level (one side): " + minConfidenceLevelOneSide);

		// Accuracy
		final double accuracy = 0.0000000001;

		// Calculate maximum for each output
		double sumLwMax = 0.0;
		
		for(int j = 0; j < matrix[0].length; j++) {
			// Calculate the binomial distributions of estimated probabilities
			ArrayList<BinomialDist> B = new ArrayList<BinomialDist>();
			for(int i = 0; i < matrix.length; i++) {
				//System.out.println("matrix[" + i + "][" + j + "] = " + condProb[i][j]);
				//System.out.println("sampleNum = " + sampleSizeGivenInput[i]);
				// TODO: This binomial distribution is a temporal version, we need to update.
				B.add(new BinomialDist(sampleSizeGivenInput[i], matrix[i][j]));
			}
			
			// Stop estimating confidence interval when #inputs > 2^20
			if(matrix.length > Math.pow(2, 20)) {
				System.out.println("Error: The number of distinct inputs is so large that the");
				System.out.println("       estimate of confidence interval may be inaccurate.");
				System.exit(1);
			}

			// Joint confidence level
			final double jointPopulationOneSide = Math.pow(minConfidenceLevelOneSide, 1.0/(double)B.size());
			
			// Calculate the lower bound of the maximum of the
			// joint probabilities of having the same output
			double lwMax = 0.0;
			for(int i = 0; i < matrix.length; i++) {
				double upper = B.get(i).WilsonIntervalUpper(jointPopulationOneSide, accuracy);
				double upperNorm = B.get(i).upperBoundNormal95();
				//
				//double lower = B.get(i).WilsonIntervalLower(jointPopulationOneSide, accuracy);
				//double center = B.get(i).WilsonIntervalUpper(0.5, accuracy);
				//System.out.println("  upper:    " + upper);
				//System.out.println("  lower:    " + lower);
				//System.out.println("  centerER: " + (center - matrix[i][j]));
				//double lowerNorm = B.get(i).lowerBoundNormal95();
				//System.out.println("  upperNorm: " + upperNorm);
				//System.out.println("  lowerNorm: " + lowerNorm);
				//
				double distance = upper - matrix[i][j];
				//System.out.println("  distance: " + distance);
				double candidate = Math.max(0.0, pmf[i] * (matrix[i][j] - distance));
				//double cand = (condProb[i][j] - distance);
				//System.out.println("  candidate:" + candidate);
				if(candidate > lwMax)  lwMax = candidate;
			}
			//System.out.println("  lwMax: " + lwMax);
			//System.out.println("  ------");
			
			sumLwMax += lwMax;
		}
		//System.out.println("  sumLwMax: " + sumLwMax);

		// Calculate the lower/upper bounds of the confidence interval
		double lowerCondMinEntropy = InfoTheory.log2(sumLwMax);
		//System.out.println("lowerCondMinEntropy: " + lowerCondMinEntropy);
		//System.out.println("MinEntropy of input: " + InfoTheory.minEntropy(dist));
		double lowerBoundInterval = Math.max(InfoTheory.minEntropy(pmf) + lowerCondMinEntropy, 0.0);

		return lowerBoundInterval;
	}
	*/
	
	/*
	 * Calculates the upper bound of the confidence interval of
	 * the estimated min-entropy leakage.
	 * 
	 * @param pmf pmf array
	 * @param matrix channel matrix
	 * @param sampleSizeGivenInput the numbers of samples with given inputs
	 * @return the maximum possible error of the estimated min-entropy leakage 
	 */
	/*
	public static double minEntropyLeakUpperBoundBinomial(double[] pmf, double[][] matrix, int[] sampleSizeGivenInput) {
		// Confidence level
		final double minConfidenceLevel = 0.95;
		final double minConfidenceLevelOneSide = minConfidenceLevel + (1 - minConfidenceLevel)/2.0;
		//System.out.println("Minimum confidence level: " + minConfidenceLevel);
		//System.out.println("Minimum confidence level (one side): " + minConfidenceLevelOneSide);

		// Accuracy
		final double accuracy = 0.0000000001;

		// Calculate maximum for each output
		double sumUpMax = 0.0;
		
		for(int j = 0; j < matrix[0].length; j++) {
			// Calculate the binomial distributions of estimated probabilities
			ArrayList<BinomialDist> B = new ArrayList<BinomialDist>();
			for(int i = 0; i < matrix.length; i++) {
				//System.out.println("matrix[" + i + "][" + j + "] = " + condProb[i][j]);
				//System.out.println("sampleNum = " + sampleSizeGivenInput[i]);
				// TODO: This binomial distribution is a temporal version, we need to update.
				B.add(new BinomialDist(sampleSizeGivenInput[i], matrix[i][j]));
			}
			
			// Stop estimating confidence interval when #inputs > 2^20
			if(matrix.length > Math.pow(2, 20)) {
				System.out.println("Error: The number of distinct inputs is so large that the");
				System.out.println("       estimate of confidence interval may be inaccurate.");
				System.exit(1);
			}

			// Joint confidence level
			final double jointPopulationOneSide = Math.pow(minConfidenceLevelOneSide, 1.0/(double)B.size());
			
			// Calculate the upper bound of the maximum of the
			// joint probabilities of having the same output
			double upMax = 0.0;
			for(int i = 0; i < matrix.length; i++) {
				double lower = B.get(i).WilsonIntervalLower(jointPopulationOneSide, accuracy);
				double lowerNorm = B.get(i).lowerBoundNormal95();
				//
				//double upper = B.get(i).WilsonIntervalUpper(jointPopulationOneSide, accuracy);
				//double center = B.get(i).WilsonIntervalUpper(0.5, accuracy);
				//System.out.println("  upper:    " + upper);
				//System.out.println("  lower:    " + lower);
				//System.out.println("  centerER: " + (center - matrix[i][j]));
				//double upperNorm = B.get(i).upperBoundNormal95();
				//System.out.println("  upperNorm: " + upperNorm);
				//System.out.println("  lowerNorm: " + lowerNorm);
				//
				double distance = matrix[i][j] - lower;
				//System.out.println("  distance: " + distance);
				double candidate = Math.max(0.0, pmf[i] * (matrix[i][j] + distance));
				//double candidate = (condProb[i][j] + distance);
				//System.out.println("  candidate:" + candidate);
				if(candidate > upMax)  upMax = candidate;
			}
			//System.out.println("  upMax: " + upMax);
			//System.out.println("--------------------------------- ");
			sumUpMax += upMax;
		}
		//System.out.println("  sumUpMax: " + sumUpMax);

		// Calculate the lower/upper bounds of the confidence interval
		double upperCondMinEntropy = InfoTheory.log2(sumUpMax);
		//System.out.println("upperCondMinEntropy: " + upperCondMinEntropy);
		//System.out.println("MinEntropy of input: " + InfoTheory.minEntropy(dist));
		double upperBoundInterval = Math.min(InfoTheory.minEntropy(pmf) + upperCondMinEntropy, InfoTheory.log2(pmf.length));

		return upperBoundInterval;
	}
	*/
	
	
	/////////////////////////////////
	// Calculation of min-capacity //
	/**
	 * Calculates the min-capacity of a channel.
	 * 
	 * @param channel channel
	 * @return the min-capacity of channel
	 */
	public static double minCapacity(Channel channel) {
		return minCapacity(channel.getMatrix());
	}
}
