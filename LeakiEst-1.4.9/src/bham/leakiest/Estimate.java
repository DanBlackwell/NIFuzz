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
package bham.leakiest;

import bham.leakiest.infotheory.*;

/**
 * This is the class of the APIs for estimating information
 * leakage of a system.
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.4.5
 */
public class Estimate {
	// Constant
	private static final double ERROR = TestInfoLeak.ERROR;
	
	public Estimate() {
		TestInfoLeak.verbose = 0;
	}

	public Estimate(int verbose) {
		TestInfoLeak.verbose = verbose;
	}

	////////////////////////////////////////////////////////////////
	////// Leakage estimation functions for mutual information /////
	////// when the input distribution is also estimated       /////
	/**
	 * Calculates the mutual information from given observations.
	 * @param obs Observations
	 * @return Mutual information
	 */
	public static double getMutualInformation(Observations obs) {
		ProbDist pd = obs.getInputProbDist();
		Channel channel = obs.generateChannel();
		return ShannonEntropy.mutualInformation(pd, channel);
		//return ShanonEntropy.MIuniformInput(obs.getChannelMatrix());
	}

	/**
	 * Calculates the corrected mutual information from given observations.
	 * @param obs Observations
	 * @return Corrected mutual information
	 */
	public static double getCorrectedMutualInformation(Observations obs) {
		double correction = ((double)obs.getDegreeOfFreedomMI())
						  / (double)(2 * obs.getSampleCount()) * InfoTheory.log2(Math.E);
		return Math.max(0.0, getMutualInformation(obs) - correction);
	}
	
	/**
	 * Calculates the corrected mutual information from given observations.
	 * @param obs Observations
	 * @return Corrected mutual information
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMutualInformation(Observations obs) {
		double correction = ((obs.getUniqueInputCount() - 1) * (obs.getUniqueOutputCount() - 1))
						  / (double)(2 * obs.getSampleCount()) * InfoTheory.log2(Math.E);
		return Math.max(0.0, getMutualInformation(obs) - correction);
	}

    /**
     * Calculates the variance for an estimated non-zero mutual information estimate
     * when the input distribution is also estimated from the sample.
     * <BR>
	 * variance equals 1/N.&Sigma;_x p(x).(
	 *      (   ( &Sigma;_y p(y|x). (log( p(x,y) / (p(x). p(y)) ))^2)
     *        - (  ( &Sigma;_y p(y|x).log( p(x,y) / (p(x). p(y)) ) )^2) ) )
     * 
     * @param pmf input PMF array
     * @param W channel matrix
     * @param sampleSize sample size
     * @return the variance for an estimated non-zero mutual information estimate
     *         when the input distribution is also estimated from the sample
     */
	protected static double VarianceOfEstimatedMIUnderEstimatedPrior(double[] pmf, double[][] W, int sampleSize) {
		double result = 0;
		for(int x = 0; x < W.length; x++) { //Sigma_x
			double firstPart = 0; // =(\Sigma_y W[y|x]. (log( (pmf[x].W[y|x]) / Sigma_{x'} pmf[x'].W[y|x']))^2)
			double secondPart = 0;// =(\Sigma_y W[y|x].log( (pmf[x].W[y|x]) / Sigma_{x'} pmf[x'].W[y|x']))^2
			
			for(int y = 0; y < (W[0]).length; y++) { //Sigma_y
				if(W[x][y] != 0 && pmf[x] != 0) {
					double jointProb = pmf[x]*W[x][y];
					firstPart += W[x][y]*Math.pow(InfoTheory.log2( jointProb / (pmf[x] * InfoTheory.outputProb(y,pmf,W))), 2);
					//System.out.println("firstPart  = "+ firstPart  + " <= " + pmf[x] + ", " + W[x][y] + ", " + InfoTheory.outputProb(y,pmf,W));
				}
			}
			
			for(int y = 0; y < (W[0]).length; y++) { //Sigma_y
				if(W[x][y] != 0 && pmf[x] != 0) {
					double jointProb = pmf[x]*W[x][y];
					secondPart += W[x][y]*InfoTheory.log2( jointProb / (pmf[x] * InfoTheory.outputProb(y,pmf,W)));
					//System.out.println("secondPart = "+ secondPart + " <= " + pmf[x] + ", " + W[x][y] + ", " + InfoTheory.outputProb(y,pmf,W));
				}
			}
			secondPart = Math.pow(secondPart, 2);

			result += pmf[x]*(firstPart - secondPart);
		}
		return ((1/(double)sampleSize)*result);//  * Math.pow(InfoTheory.log2(Math.E),2);
		// TODO: the variace has already transformed from base e to 2 
		//       by using log2 rather than Math.log, so
		//       I removed the multiplication by log2(e)^2 here.
	}
	
	/**
     * Calculates the variance for an estimated non-zero mutual information estimate
     * when the input distribution is also estimated from the sample.
	 * 
	 * @param pd (prior) input probability distribution
	 * @param channel channel
     * @param sampleSize sample size
     * @return the variance for an estimated non-zero mutual information estimate
     *         when the input distribution is also estimated from the sample
	 */
	public static double VarianceOfEstimatedMIUnderEstimatedPrior(ProbDist pd, Channel channel, int sampleSize) {
		double[] pmf;
		if(pd != null)
			pmf = pd.probDistToPMFArray(channel.getInputNames());
		else
			pmf = ProbDist.uniformProbArray(channel.noOfInputs());
		double[][] matrix = channel.getMatrix();
		if(pmf != null)
			return VarianceOfEstimatedMIUnderEstimatedPrior(pmf, matrix, sampleSize);
		else
			return (double)ERROR;
	}
	
	/**
	 * Calculates the lower bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @return Lower bound of the confidence interval (95%) of mutual information
	 */
	public static double getCorrectedMutualInformationLowerBound(Observations obs) {
		ProbDist pd = obs.getInputProbDist();
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(obs.getDegreeOfFreedomMI())
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderEstimatedPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		return lower;
	}

	/**
	 * Calculates the lower bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @return Lower bound of the confidence interval (95%) of mutual information
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMutualInformationLowerBound(Observations obs) {
		ProbDist pd = obs.getInputProbDist();
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(channel.noOfInputs() - 1) * (double)(channel.noOfOutputs() - 1)
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderEstimatedPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		return lower;
	}

	/**
	 * Calculates the upper bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @return Upper bound of the confidence interval (95%) of mutual information
	 */
	public static double getCorrectedMutualInformationUpperBound(Observations obs) {
		ProbDist pd = obs.getInputProbDist();
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(obs.getDegreeOfFreedomMI())
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderEstimatedPrior(pd, channel, sampleSize);
		double upper = Stats.upperBoundNormal95(mean, variance);
		return upper;
	}

	/**
	 * Calculates the upper bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @return Upper bound of the confidence interval (95%) of mutual information
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMutualInformationUpperBound(Observations obs) {
		ProbDist pd = obs.getInputProbDist();
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(channel.noOfInputs() - 1) * (double)(channel.noOfOutputs() - 1)
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderEstimatedPrior(pd, channel, sampleSize);
		double upper = Stats.upperBoundNormal95(mean, variance);
		return upper;
	}

	/**
	 * Calculates the confidence interval for corrected mutual information from
	 * given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @return Confidence interval
	 */
	public static double getCorrectedMutualInformationConfidenceInterval(Observations obs) {
		Channel channel = obs.generateChannel();
		ProbDist pd = obs.getInputProbDist();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(obs.getDegreeOfFreedomMI())
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderEstimatedPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		double upper = Stats.upperBoundNormal95(mean, variance);
		
		/*
		System.out.println("--------------------------------------------");
		System.out.println("result = " + result);
		System.out.println("correction = " + correction);
		System.out.println("mean = " + mean);
		System.out.println("variance = " + variance);
		System.out.println("lower = " + lower);
		System.out.println("upper = " + upper);
		System.out.println("--------------------------------------------");
		*/
		
		return Stats.round((upper - lower) / 2, 4);
	}

	/**
	 * Calculates the confidence interval for corrected mutual information from
	 * given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @return Confidence interval
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMutualInformationConfidenceInterval(Observations obs) {
		Channel channel = obs.generateChannel();
		ProbDist pd = obs.getInputProbDist();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(channel.noOfInputs() - 1) * (double)(channel.noOfOutputs() - 1)
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderEstimatedPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		double upper = Stats.upperBoundNormal95(mean, variance);
		
		/*
		System.out.println("--------------------------------------------");
		System.out.println("result = " + result);
		System.out.println("correction = " + correction);
		System.out.println("mean = " + mean);
		System.out.println("variance = " + variance);
		System.out.println("lower = " + lower);
		System.out.println("upper = " + upper);
		System.out.println("--------------------------------------------");
		*/
		
		return Stats.round((upper - lower) / 2, 4);
	}

	/**
	 * Calculates the variance of the estimated mutual information
	 * from given observations
     * when the input distribution is also estimated from the sample.
	 * 
	 * @param obs observations
	 * @return the variance of the estimated mutual information
     * when the input distribution is also estimated from the sample
	 */
	public static double getVariance(Observations obs) {
		return VarianceOfEstimatedMIUnderEstimatedPrior(obs.getInputProbDist(), obs.generateChannel(), obs.getSampleCount());
	}

	/**
	 * Calculates the upper bound for zero leakage from given observations.
	 * If the number of inputs is less than 1 or that of outputs is less than 1,
	 * then this method returns -1.
	 * @param obs Observations
	 * @return Upper bound for zero leakage
	 */
	public static double getUpperBoundForZeroLeakage(Observations obs) {
		if(obs.getUniqueInputCount() < 1 || obs.getUniqueOutputCount() <1) {
			return -1;
		} else {
			return Stats.upperBoundForZero((obs.getUniqueInputCount() - 1) * (obs.getUniqueOutputCount() - 1), obs.getSampleCount());
		}
	}

	
	////////////////////////////////////////////////////////////////
	////// Leakage estimation functions for mutual information /////
	////// when the input distribution is known                /////
	/*
	 * Calculates the corrected mutual information from given observations
	 * when the prior is known.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Corrected mutual information
	 */
	public static double getCorrectedMutualInformationWithKnownPrior(Observations obs, ProbDist pd) {
		double correction = ((double)obs.getDegreeOfFreedomMI())
				          / (double)(2 * obs.getSampleCount()) * InfoTheory.log2(Math.E);
		Channel channel = obs.generateChannel();
		double MI = ShannonEntropy.mutualInformation(pd, channel);
		return Math.max(0.0, MI - correction);
	}
	
	/**
	 * Calculates the corrected mutual information from given observations
	 * when the prior is known.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Corrected mutual information
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMutualInformationWithKnownPrior(Observations obs, ProbDist pd) {
		double correction = ((obs.getUniqueInputCount() - 1) * (obs.getUniqueOutputCount() - 1))
				          / (double)(2 * obs.getSampleCount()) * InfoTheory.log2(Math.E);
		Channel channel = obs.generateChannel();
		double MI = ShannonEntropy.mutualInformation(pd, channel);
		return Math.max(0.0, MI - correction);
	}
	
	/**
     * Calculates the variance for an estimated non-zero mutual information estimate
     * when the input distribution is known.
     * <BR>
	 * variance equals 1/N.&Sigma;_x p(x).(
	 *      (   ( &Sigma;_y p(y|x). (log( p(x,y) / p(y) ))^2)
     *        - (  ( &Sigma;_y p(y|x).log( p(x,y) / p(y) ) )^2) ) )
     * 
     * @param pmf input PMF array
     * @param W channel matrix
     * @param sampleSize the sample size
     * @return the variance for an estimated non-zero mutual information estimate
     *         when the input distribution is known
     */
	protected static double VarianceOfEstimatedMIUnderKnownPrior(double[] pmf, double[][] W, int sampleSize) {
		double result = 0;
		for(int x = 0; x < W.length; x++) { //Sigma_x
			double firstPart = 0; // =(\Sigma_y W[y|x]. (log( (pmf[x].W[y|x]) / Sigma_{x'} pmf[x'].W[y|x']))^2)
			double secondPart = 0;// =(\Sigma_y W[y|x].log( (pmf[x].W[y|x]) / Sigma_{x'} pmf[x'].W[y|x']))^2
			
			for(int y = 0; y < (W[0]).length; y++) { //Sigma_y
				if(W[x][y] != 0 && pmf[x] != 0) {
					double jointProb = pmf[x]*W[x][y];
					firstPart += W[x][y]*Math.pow(InfoTheory.log2( jointProb / InfoTheory.outputProb(y,pmf,W)),2);
				}
			}
			
			for(int y = 0; y < (W[0]).length; y++) { //Sigma_y
				if(W[x][y] != 0 && pmf[x] != 0) {
					double jointProb = pmf[x]*W[x][y];
					secondPart += W[x][y]*InfoTheory.log2( jointProb / InfoTheory.outputProb(y,pmf,W));
				}
			}
			secondPart = Math.pow(secondPart, 2);
			
			result += pmf[x]*(firstPart - secondPart);
		}
		return ((1/(double)sampleSize)*result);//  * Math.pow(InfoTheory.log2(Math.E),2);
		// TODO: the variace has already transformed from base e to 2 
		//       by using log2 rather than Math.log, so
		//       I removed the multiplication by log2(e)^2 here.
	}

	/**
     * Calculates the variance for an estimated non-zero mutual information estimate
     * when the input distribution is known.
	 * 
	 * @param pd (prior) input probability distribution
	 * @param channel channel
     * @param sampleSize sample size
     * @return the variance for an estimated non-zero mutual information estimate
     *         when the input distribution is known
	 */
	public static double VarianceOfEstimatedMIUnderKnownPrior(ProbDist pd, Channel channel, int sampleSize) {
		double[] pmf;
		if(pd != null)
			pmf = pd.probDistToPMFArray(channel.getInputNames());
		else
			pmf = ProbDist.uniformProbArray(channel.noOfInputs());
		double[][] matrix = channel.getMatrix();
		if(pmf != null)
			return VarianceOfEstimatedMIUnderKnownPrior(pmf, matrix, sampleSize);
		else
			return (double)ERROR;
	}

	/**
	 * Calculates the lower bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Lower bound of the confidence interval (95%) of mutual information
	 */
	public static double getCorrectedMILowerBoundUnderKnownPrior(Observations obs, ProbDist pd) {
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = ((double)obs.getDegreeOfFreedomMI())
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderKnownPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		return lower;
	}

	/**
	 * Calculates the lower bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Lower bound of the confidence interval (95%) of mutual information
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMILowerBoundUnderKnownPrior(Observations obs, ProbDist pd) {
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(channel.noOfInputs() - 1) * (double)(channel.noOfOutputs() - 1)
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderKnownPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		return lower;
	}

	/**
	 * Calculates the upper bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Upper bound of the confidence interval (95%) of mutual information
	 */
	public static double getCorrectedMIUpperBoundUnderKnownPrior(Observations obs, ProbDist pd) {
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = ((double)obs.getDegreeOfFreedomMI())
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderKnownPrior(pd, channel, sampleSize);
		double upper = Stats.upperBoundNormal95(mean, variance);
		return upper;
	}

	/**
	 * Calculates the upper bound of the confidence interval (95%)
	 * of mutual information from given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Upper bound of the confidence interval (95%) of mutual information
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMIUpperBoundUnderKnownPrior(Observations obs, ProbDist pd) {
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(channel.noOfInputs() - 1) * (double)(channel.noOfOutputs() - 1)
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderKnownPrior(pd, channel, sampleSize);
		double upper = Stats.upperBoundNormal95(mean, variance);
		return upper;
	}

	/**
	 * Calculates the confidence interval for corrected mutual information from
	 * given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Confidence interval
	 */
	public static double getCorrectedMIConfidenceIntervalUnderKnownPrior(Observations obs, ProbDist pd) {
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = ((double)obs.getDegreeOfFreedomMI())
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderKnownPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		double upper = Stats.upperBoundNormal95(mean, variance);
		
		/*
		System.out.println("--------------------------------------------");
		System.out.println("result = " + result);
		System.out.println("correction = " + correction);
		System.out.println("mean = " + mean);
		System.out.println("variance = " + variance);
		System.out.println("lower = " + lower);
		System.out.println("upper = " + upper);
		System.out.println("--------------------------------------------");
		*/
		
		return Stats.round((upper - lower) / 2, 4);
	}
	
	/**
	 * Calculates the confidence interval for corrected mutual information from
	 * given observations
     * when the input distribution is also estimated from the sample.
	 * @param obs Observations
	 * @param pd prior distribution
	 * @return Confidence interval
	 * @deprecated This method is only for confirming the old implementation and should be replaced with another method.
	 */
	public static double getOldCorrectedMIConfidenceIntervalUnderKnownPrior(Observations obs, ProbDist pd) {
		Channel channel = obs.generateChannel();
		double result = ShannonEntropy.mutualInformation(pd, channel);
		int sampleSize = obs.getSampleCount();
		double correction = (double)(channel.noOfInputs() - 1) * (double)(channel.noOfOutputs() - 1)
						  / (double)(2 * sampleSize) * InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);
		double variance = VarianceOfEstimatedMIUnderKnownPrior(pd, channel, sampleSize);
		double lower = Math.max(0.0, Stats.lowerBoundNormal95(mean, variance));
		double upper = Stats.upperBoundNormal95(mean, variance);
		
		/*
		System.out.println("--------------------------------------------");
		System.out.println("result = " + result);
		System.out.println("correction = " + correction);
		System.out.println("mean = " + mean);
		System.out.println("variance = " + variance);
		System.out.println("lower = " + lower);
		System.out.println("upper = " + upper);
		System.out.println("--------------------------------------------");
		*/
		
		return Stats.round((upper - lower) / 2, 4);
	}
	
	
	/////////////////////////////////////////////////////
	////// Leakage estimation functions for capacity/////
	// Parameters for capacity
	private static double acceptableError = TestInfoLeak.acceptableError;
	private static int noOfIterations = TestInfoLeak.noOfIterations;
	
	/**
	 * Calculates the channel capacity from given observations.
	 * If Blahut-Arimoto Algorithm did not terminate and
	 * error is not acceptable, this method returns -1.
	 * @param obs Observations
	 * @return Channel capacity
	 */
	public static double getCapacity(Observations obs) {
		//Calculate the channel
		Channel channel = obs.generateChannel();
		//Find the capacity of a basic channel
		BlahutArimoto ba = new BlahutArimoto(channel, acceptableError, noOfIterations);
		ba.calculateCapacity();

		// Error
		double possibleError = ba.getPossibleError();
		double acceptableError = ba.getAcceptableError();

		if(possibleError <= acceptableError) { //Blahut-Arimoto Algorithm terminated or error is acceptable.
			return ba.getCapacity();
		} else { //Blahut-Arimoto Algorithm did not terminate and error is not acceptable.
			return -1;
		}
	}

	/**
	 * Calculates the input distribution that gives the channel capacity.
	 * If Blahut-Arimoto Algorithm did not terminate and
	 * error is not acceptable, this method returns null.
	 * @param obs Observations
	 * @return Input distribution that gives the channel capacity
	 */
	public static double[] getInputDistYieldingCapacity(Observations obs) {
		//Calculate the channel
		Channel channel = obs.generateChannel();
		//Find the capacity of a basic channel
		BlahutArimoto ba = new BlahutArimoto(channel, acceptableError, noOfIterations);
		ba.calculateCapacity();
		
		// Error
		double possibleError = ba.getPossibleError();
		double acceptableError = ba.getAcceptableError();

		if(possibleError <= acceptableError) { //Blahut-Arimoto Algorithm terminated or error is acceptable.
			return ba.getMaxInputDist();
		} else { //Blahut-Arimoto Algorithm did not terminate and error is not acceptable.
			return null;
		}
	}

	/**
	 * Calculates the input distribution that gives the channel capacity.
	 * @param obs Observations
	 * @return Input distribution that gives the channel capacity
	 */
	public static double getPossibleErrorOfCapacity(Observations obs) {
		//Calculate the channel
		Channel channel = obs.generateChannel();
		BlahutArimoto ba = new BlahutArimoto(channel, acceptableError, noOfIterations);
		ba.calculateCapacity();
		return ba.getPossibleError();
	}

	/**
	 * Calculates the corrected channel capacity from given observations.
	 * If Blahut-Arimoto Algorithm did not terminate and
	 * error is not acceptable, this method returns -1.
	 * @param obs Observations
	 * @return Corrected channel capacity
	 */
	public static double getCorrectedCapacity(Observations obs) {
		//Calculate the channel
		Channel channel = obs.generateChannel();
		//Find the capacity of a basic channel
		BlahutArimoto ba = new BlahutArimoto(channel, acceptableError, noOfIterations);
		ba.calculateCapacity();

		// Error
		double possibleError = ba.getPossibleError();
		double acceptableError = ba.getAcceptableError();

		if(possibleError <= acceptableError) { //Blahut-Arimoto Algorithm terminated or error is acceptable.
			double correction = (obs.getUniqueInputCount() - 1) * (obs.getUniqueOutputCount() - 1)
					  / (double)(2 * obs.getSampleCount()) * InfoTheory.log2(Math.E);
			return Math.max(0.0, ba.getCapacity() - correction);
		} else { //Blahut-Arimoto Algorithm did not terminate and error is not acceptable.
			return -1;
		}
	}


	/////////////////////////////////////////////////////////////////
	////// Leakage estimation functions for min-entropy leakage /////
	/**
	 * Calculates the min-entropy leakage from given observations.
	 * @param obs Observations
	 * @return Min-entropy leakage
	 */
	public static double getMinEntropyLeak(Observations obs) {
		return MinEntropy.minEntropyLeak(InfoTheory.uniformDist(obs.getChannelMatrix().length), obs.getChannelMatrix());
	}

	/**
	 * Calculates the lower bound of the confidence interval (95%)
	 * of min-entropy leakage from a given chanel.
	 * @param obs Observations
	 * @return Lower bound of the confidence interval (95%) of min-entropy leakage
	 */
	public static double getMinEntropyLeakLowerBound(Observations obs) {
		return MinEntropy.minEntropyLeakLowerBoundConfidenceIntervalChiSquare(obs);
	}

	/**
	 * Calculates the upper bound of the confidence interval (95%)
	 * of min-entropy leakage from a given chanel.
	 * @param obs Observations
	 * @return Upper bound of the confidence interval (95%) of min-entropy leakage
	 */
	public static double getMinEntropyLeakUpperBound(Observations obs) {
		return MinEntropy.minEntropyLeakUpperBoundConfidenceIntervalChiSquare(obs);
	}


	////////////////////////////////////////////////////////////////////
	////// Leakage estimation functions for posterior min-capacity /////
	/**
	 * Calculates the conditional min-entropy leakage from given observations.
	 * @param obs Observations
	 * @return Conditional min-entropy leakage
	 */
	public static double getCondMinEntropy(Observations obs) {
		return MinEntropy.conditionalMinEntropy(InfoTheory.uniformDist(obs.getChannelMatrix().length), obs.getChannelMatrix());
	}

	/**
	 * Calculates the lower bound of the confidence interval (95%)
	 * of conditional min-entropy from a given chanel.
	 * @param obs Observations
	 * @return Lower bound of the confidence interval (95%) of conditional min-entropy
	 */
	public static double getCondMinEntropyLowerBound(Observations obs) {
		return MinEntropy.minConditionalEntropyLowerBoundConfidenceIntervalChiSquare(obs);
	}

	/**
	 * Calculates the upper bound of the confidence interval (95%)
	 * of conditional min-entropy from a given chanel.
	 * @param obs Observations
	 * @return Upper bound of the confidence interval (95%) of conditional min-entropy
	 */
	public static double getCondMinEntropyUpperBound(Observations obs) {
		return MinEntropy.minConditionalEntropyUpperBoundConfidenceIntervalChiSquare(obs);
	}

	//////////////////////////////////////////////////////////
	////// Leakage estimation functions for min-capacity /////
	/**
	 * Calculates the min-capacity leakage from given observations.
	 * @param obs Observations
	 * @return Min-capacity leakage
	 */
	public static double getMinCapacity(Observations obs) {
		return MinEntropy.minCapacity(obs.getChannelMatrix());
	}
	
}
