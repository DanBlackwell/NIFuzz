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

/**
 * This is the class that contains methods for the input approximation
 * technique for the compositional reasoning of leakages.
 *
 * @author Yusuke Kawamoto
 * @version 1.3
 */

import java.util.Arrays;
import java.util.TreeSet;
import java.util.HashMap;
import bham.leakiest.infotheory.*;

public class ApproxPrior {
    private static int verbose = TestInfoLeak.verbose;
	private static final double ERROR = ProbDist.ERROR;
	private static final double accuracy = ProbDist.accuracy;
	private	static State stateMinimum;
	private static State stateMaximum;
	private	static double MInfMin;
	private static double MInfMax;

	/*
	 * 
	 * @param jpd joint input distribution
	 * @param marginals the list of all marginal probability distributions
	 * @param totalOfAddedValues
	 * @param numChannels the number of channels composed
	 * @return
	 */
	private static ProbDist MInfAux(ProbDist jpd, ProbDist[] marginals, double totalOfAddedValues, int numChannels) {
		System.out.println("Joint (prior) input distribution before the modification:");
		jpd.printProbDist();
		
		// Calculate the array of MInf (and also M_Inf^min and M_Inf^max)
		TreeSet<Double> MInf = new TreeSet<Double>();
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
				
				// add the value of frac to the tree set MInf
				MInf.add(frac);
				
				// calculate the minimum (M_Inf^min) and minimizing state
				double prevMinimum = minimum;
				minimum = Math.min(minimum, frac);
				if(minimum != prevMinimum) 	stateMinimum = jst;
				
				// calculate the maximum (M_Inf^max) and maximizing state
				double prevMaximum = maximum;
				maximum = Math.max(maximum, frac);
				if(maximum != prevMaximum) 	stateMaximum = jst;
				
			}
		}
		MInfMin = minimum;
		MInfMax = maximum;
		if(verbose >= 5) {
			System.out.println("  minimum = " + minimum);
			System.out.println("  maximum = " + maximum);
			System.out.println("  totalOfAddedValues = " + totalOfAddedValues);
		}

		// Calculate the size and minimum probability of the modified prior
		int sizeSampleSpace = jpd.sizeSampleSpace();
		int sizeModifiedPrior = 0;
		double minModifiedPrior = 0.0;
		double sum = 0.0;
		int count = 0;
		for(double d : MInf) {
	    	System.out.println("  pmf[" + count + "] = " + d);
			if(sum + d <= totalOfAddedValues) {
				sum += d;
				count++;
		    	//System.out.println("  should modify pmf[" + count + "] = " + d);
			} else {
				sizeModifiedPrior = sizeSampleSpace - count;
				minModifiedPrior = d;
				break;
			}
		}
		if(verbose >= 5) {
			System.out.println("  size of ModifiedPrior =                " + sizeModifiedPrior);
			System.out.println("  minimum probability of ModifiedPrior = " + minModifiedPrior);
		}
		
		int numAdded = 0;
		double remainingAddedValues = totalOfAddedValues;
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
				if(frac <= minModifiedPrior && numAdded <= sizeSampleSpace - sizeModifiedPrior && remainingAddedValues > 0) {
					double newProb = Math.min(product, remainingAddedValues);
					jpd.updateProb(jst, newProb);
					numAdded++;
					remainingAddedValues -= newProb;
					System.out.println("   = " + jprob + " => " + newProb);
				}
			}
		}
		return jpd;
	}

	
	/*
	public static double transformPrior(ProbDist pd, double sumOfSmallProbs) {
		double min = 0;
		
		return min;
	}
	*/


	/*
	private static ProbDist approxPriorToGetMoreIndependence(ProbDist pd, ProbDist[] marginals, double totalOfAddedValues, boolean lock) {
		int numChannels = marginals.length;
		ProbDist apd = MInfAux(pd, marginals, totalOfAddedValues, numChannels);	
		
		return apd;
	}
	 */
	
	/*
	 * Returns an approximate probability distribution where small probabilities
	 * are replaced with zero.
	 * This method is used when we esitmate a leakage measure of a huge composed channel.
	 * 
	 * @param pd (prior) probability distribution
	 * @param sumOfSmallProbs the summation of all small probabilities that
	 *                        will be removed from the (prior) probability distribution
	 * @param lock forbids overwriting the probability distribution
	 * @return an approximate probability distribution where small probabilities are replaced with zero
	 */
	protected static ProbDist approxPriorSmallProbsRemoved(ProbDist pd, double sumOfSmallProbs, boolean lock) {
		HashMap<State, Double> dist = new HashMap<State, Double>();
		double[] pmf = pd.getPMFArray();
		Arrays.sort(pmf);
		
		// Calculate the size and minimum probability of the modified prior
		int sizeModifiedPrior = 0;
		double minModifiedPrior = 0.0;
		double sum = 0.0;
		for(int i = 0; i < pmf.length; i++) {
			if(sum + pmf[i] <= sumOfSmallProbs) {
				sum += pmf[i];
		    	//System.out.println("  sum = " + sum + "  pmf[" + i + "] = " + pmf[i] + "  sumOfSmallProbs = " + sumOfSmallProbs);
		    	//System.out.println("  removed pmf[" + i + "] = " + pmf[i]);
			} else {
				sizeModifiedPrior = pmf.length - i;
				minModifiedPrior = pmf[i];
				break;
			}
		}
		if(verbose >= 5) {
			System.out.println("  size of ModifiedPrior =                " + sizeModifiedPrior);
			System.out.println("  minimum probability of ModifiedPrior = " + minModifiedPrior);
		}

		// Construct the approximate probability distribution
		int numRemoved = 0;
		for(State st : pd.getStatesCollection()) {
			double prob = pd.getProb(st);
			if(prob < minModifiedPrior && numRemoved < pmf.length - sizeModifiedPrior) {
				//System.out.print("  prob = " + prob);
				//System.out.print("  minModifiedPrior = " + minModifiedPrior);
				//System.out.print("  numRemoved = " + numRemoved);
				//System.out.println("  pmf.length - sizeModifiedPrior = " + (pmf.length - sizeModifiedPrior));
				prob = 0;
				numRemoved++;
			}
			dist.put(st, prob);
		}
		ProbDist apd = new ProbDist(dist, lock);
		return apd;
	}
	
	
	/*
	 * Returns the probability distribution where all probabilities but the largest ones
	 * are replaced with zero.
	 * This method is used when we esitmate a leakage measure of a huge composed channel.
	 * 
	 * @param pd (prior) probability distribution
	 * @param lock forbids overwriting the probability distribution
	 * @return the probability distribution where all probabilities but the largest ones
	 *         are replaced with zero
	 */
	protected static ProbDist approxPriorSmallProbsRemoved(ProbDist pd, boolean lock) {
		HashMap<State, Double> dist = new HashMap<State, Double>();
		double[] pmf = pd.getPMFArray();

		// Calculate the maximum probabities in the given prior
		double maxProb = 0.0;
		for(int i = 0; i < pmf.length; i++) {
			maxProb = Math.max(maxProb, pmf[i]);
		}
		
		// Construct the approximate probability distribution
		for(State st : pd.getStatesCollection()) {
			double prob = pd.getProb(st);
			if(prob < maxProb) {
				//System.out.println("  prob = " + prob);
				//System.out.println("  minModifiedPrior = " + minModifiedPrior);
				//System.out.println("  numRemoved = " + numRemoved);
				//System.out.println("  pmf.length - sizeModifiedPrior = " + (pmf.length - sizeModifiedPrior));
				prob = 0;
			}
			dist.put(st, prob);
		}
		ProbDist apd = new ProbDist(dist, lock);
		return apd;
	}


	/**
	 * Returns the summation of all probabilities removed from the input distribution,
	 * by input approximation.
	 * 
	 * @param apd approximate input distribution
	 * @return the summation of all probabilities removed from the input distribution
	 */
	public static double sumOfProbsRemoved(ProbDist apd) {
		double sumOfProbs = 0;
		for(double d : apd.getPMFArray()) {
			//System.out.println("  apd.prob = " + d);
			sumOfProbs += d;
		}
		//System.out.println("  sumOfProbs = " + sumOfProbs);
		return Math.max(0.0, 1.0 - sumOfProbs);
	}
	
	
	/**
	 * Returns an error of the leakage caused by removing small probabilities
	 * by the input approximation technique.
	 * This method is used when we esitmate a leakage measure of a huge composed channel.
	 * This error is valid if we can calculate the min-entropies of channels
	 * with the approximate input, and invalid if we cannot caluclate them.
	 * 
	 * @param apd approximate input distribution
	 * @param channels all channels that might be composed
	 * @param sumOfSmallProbs the sum of small probabilities removed from the input distribution
	 * @return an error of the leakage calculated by input approximation
	 */
	public static double[] errorMinEntropyLeakSmallProbsRemoved(ProbDist apd, Channel[] channels, double sumOfSmallProbs) {
		double[] error = new double[2];
		// approximation by removing small probabilities does not make an error of the lower bound.
		error[0] = 0.0;

		// approximation by removing small probabilities makes an error of the upper bound.
		double maxV = 0.0;
		for(Channel ch : channels) {
			maxV = Math.max(maxV, MinEntropy.conditionalVulnerability(apd, ch));
			//System.out.println("  maxV            = " + maxV);
		}
		if(verbose >= 5) {
			System.out.println("  sumOfSmallProbs = " + sumOfSmallProbs);
		}
		//error[1] = sumOfSmallProbs / maxV;
		error[1] = InfoTheory.log2(1.0 + sumOfSmallProbs / maxV);
		return error;
	}

	
	/**
	 * Returns an error of the leakage caused by removing small probabilities
	 * by the input approximation technique in the case of jointly supported
	 * input distributions.
	 * This method is used when we esitmate a leakage measure of a huge composed channel.
	 * This error is valid even if we cannot calculate the min-entropies of sub-channels
	 * while giving worse bounds.
	 * 
	 * @param pd input distribution
	 * @param channels all channels that might be composed
	 * @param sumOfSmallProbs the sum of small probabilities removed from the input distribution
	 * @return an error of the leakage calculated by input approximation
	 */
	public static double[] errorMinEntropyLeakSmallProbsRemovedNoReexecutionWithJointInput(ProbDist pd, Channel[] channels, double sumOfSmallProbs) {
		double[] error = new double[2];
		// calulcate the vulnerabilities
		double[] V = new double[channels.length];
		double maxV = 0.0;
		for(int num = 0; num < channels.length; num++) {
			V[num] = MinEntropy.conditionalVulnerability(pd, channels[num]);
			maxV = Math.max(maxV, V[num]);
			//System.out.println("  V[" + num + "] = " + V[num]);
		}
		// approximation by removing small probabilities makes an error of the lower bound.
		double sum = 0.0;
		for(int num = 0; num < channels.length; num++) {
			sum += InfoTheory.log2(V[num] / (V[num] - sumOfSmallProbs));
		}
		error[0] = - sum;
		
		// approximation by removing small probabilities makes an error of the upper bound.
		error[1] = InfoTheory.log2(maxV / (maxV - sumOfSmallProbs));
		if(verbose >= 5) {
			System.out.println("  maxOfSmallProbs = " + sumOfSmallProbs);
		}
		return error;
	}

	
	/**
	 * Returns an error of the leakage caused by removing small probabilities
	 * by the input approximation technique in the case of shared input distributions.
	 * This method is used when we esitmate a leakage measure of a huge composed channel.
	 * This error is valid even if we cannot calculate the min-entropies of sub-channels
	 * while giving worse bounds.
	 * 
	 * @param pd input distribution
	 * @param channels all channels that might be composed
	 * @param sumOfSmallProbs the sum of small probabilities removed from the input distribution
	 * @return an error of the leakage calculated by input approximation
	 */
	public static double[] errorMinEntropyLeakSmallProbsRemovedNoReexecutionWithSharedInput(ProbDist pd, Channel[] channels, double sumOfSmallProbs) {
		double[] error = new double[2];
		// approximation by removing small probabilities does not make an error of the lower bound.
		error[0] = 0.0;

		// approximation by removing small probabilities makes an error of the upper bound.
		double maxV = 0.0;
		for(Channel ch : channels) {
			maxV = Math.max(maxV, MinEntropy.conditionalVulnerability(pd, ch));
			if(verbose >= 5) {
				System.out.println("  maxV            = " + maxV);
			}
		}
		if(verbose >= 5) {
			System.out.println("  sumOfSmallProbs = " + sumOfSmallProbs);
		}
		error[1] = InfoTheory.log2(maxV / (maxV - sumOfSmallProbs));
		return error;
	}
	
	
}
