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
 * Copyright 2013 Tom Chothia and Yusuke Kawamoto
 */
package bham.leakiest;

import java.util.ArrayList;
import bham.leakiest.infotheory.*;

/**
 * This is the class that contains some general statistic methods.
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @version 1.4.5
 */
public class Stats {
	// Constant
	private static final double ERROR = TestInfoLeak.ERROR;
	
	/**
	 * Rounds the double n to dp decimal places.
	 * 
	 * @param n double value
	 * @param dp decimal places
	 * @return the result of rounding the double n to dp decimal places.
	 * @throws IllegalArgumentException If dp &lt; 0
	 */
	public static double round(final double n, int dp) {
		if (dp < 0) {
			throw new IllegalArgumentException("Parameter \"dp\" must be non-negative");
		} else {
			dp = Math.min(dp, 50);
			return (Math.rint(n*Math.pow(10,dp))/Math.pow(10,dp));
		}
	}


	////////////////////////////////////////////////////////////////
	// Maximum and minimum value in doubler array
	/**
	 * Returns an index that takes the maximum element in the array.
	 * 
	 * @param array double array
	 * @return an index that takes the maximum element in array
	 */
	public static int maxIndex(double[] array) {
		double max = array[0];
		int indexMax = 0;
		for(int index = 1; index < array.length; index++) {
			if(max < array[index]) {
				indexMax = index;
				max =  array[index];
			}
		}
		return indexMax;
	}

	/**
	 * Returns an index that takes the minimum element in the array.
	 * 
	 * @param array integer array
	 * @return an index that takes the minimum element in array
	 */
	public static int minIndex(double[] array) {
		double min = array[0];
		int indexMin = 0;
		for(int index = 1; index < array.length; index++) {
			if(min > array[index]) {
				indexMin = index;
				min =  array[index];
			}
		}
		return indexMin;
	}

	////////////////////////////////////////////////////////////////
	// Maximum and minimum value in integer array/list
	/**
	 * Returns an index that takes the maximum element in the array.
	 * 
	 * @param array integer array
	 * @return an index that takes the maximum element in array
	 */
	public static int maxIndex(int[] array) {
		int max = array[0];
		int indexMax = 0;
		for(int index = 1; index < array.length; index++) {
			if(max < array[index]) {
				indexMax = index;
				max =  array[index];
			}
		}
		return indexMax;
	}

	/**
	 * Returns an index that takes the minimum element in the array.
	 * 
	 * @param array integer array
	 * @return an index that takes the minimum element in array
	 */
	public static int minIndex(int[] array) {
		int min = array[0];
		int indexMin = 0;
		for(int index = 1; index < array.length; index++) {
			if(min > array[index]) {
				indexMin = index;
				min =  array[index];
			}
		}
		return indexMin;
	}

	/**
	 * Returns an index that takes the maximum element in the array list.
	 * 
	 * @param array integer array list
	 * @return an index that takes the maximum element in array
	 */
	public static int maxIndex(ArrayList<Integer> array) {
		int max = array.get(0);
		int indexMax = 0;
		for(int index = 1; index < array.size(); index++) {
			if(max < array.get(index)) {
				indexMax = index;
				max =  array.get(index);
			}
		}
		return indexMax;
	}

	/**
	 * Returns an index that takes the minimum element in the array list.
	 * 
	 * @param array integer array list
	 * @return an index that takes the minimum element in array
	 */
	public static int minIndex(ArrayList<Integer> array) {
		int min = array.get(0);
		int indexMin = 0;
		for(int index = 1; index < array.size(); index++) {
			if(min > array.get(index)) {
				indexMin = index;
				min =  array.get(index);
			}
		}
		return indexMin;
	}

	////////////////////////////////////////////////////////////////
	// Chi-square statistics
	/**
	 * &chi;-squared distribution.
	 * chiSquareValues95[i] is the 95% value for the &chi;-square distribution with i+1 degrees of freedom.
	 */
	public static double[] chiSquareValues95 = {3.841,5.991,7.815,9.488,11.07,12.59,14.07,15.51,16.92,18.31,19.68,21.03,22.36,23.69,25.00,26.30,27.59,28.87,30.14,31.41,32.67,33.92,35.17,36.42,37.65,38.89,40.11,41.34,42.56,43.77,44.99,46.19,47.40,48.60,49.80,51.00,52.19,53.38,54.57,55.76,56.94,58.12,59.30,60.48,61.66,62.83,64.00,65.17,66.34,67.51,68.67,69.83,70.99,72.15,73.31,74.47,75.62,76.78,77.93,79.08,80.23,81.38,82.53,83.68,84.82,85.97,87.11,88.25,89.39,90.53,91.67,92.81,93.95,95.08,96.22,97.35,98.49,99.62,100.75,101.88,103.01,104.14,105.27,106.40,107.52,108.65,109.77,110.90,112.02,113.15,114.27,115.39,116.51,117.63,118.75,119.87,120.99,122.11,123.23,124.34}; 
	
	/**
	 * Returns the upper bound for the 95% confidence interval
	 * for the &chi;-squared distribution with n degrees of freedom.
	 * @param freedom freedom
	 * @return the upper bound for the 95% confidence interval
	 * @throws IllegalArgumentException If freedom &le; 0
	 */
	public static double chiSqu95Interval(int freedom) {
		if (freedom <= 0) {
			throw new IllegalArgumentException("Parameter \"freedom\" must be greater than 0");
		} else if (freedom < 101) {
			return chiSquareValues95[freedom-1];
		} else {
			// approximate chi-squared distribution with > 100 degrees of freedom as normal
			// chi ~ N(freedom,2freesom)
			// 95% Z value ~ 1.65
			
			// Z = (? - freedom)/Math.sqrt(2.freedom)
			// ? = Z.Math.sqrt(2.freedom)+freedom
			return (1.644854*Math.sqrt(2*freedom)+freedom);
		}
	}

	/**
	 * Returns &chi;-square value given observed counts and expected counts.
	 * 
	 * @param observedCounts array of observed counts 
	 * @param expectedCounts array of expected counts
	 * @return &chi;-square value
	 */
    public static double chiSquare(int[] observedCounts, double[] expectedCounts) {
    	if(observedCounts.length != expectedCounts.length) {
    		System.out.println("Error: the lengths of arrays of observed and expected counts are different.");
    		System.exit(1);
    	}
    	double chisq = 0.0;
        for (int i = 0; i < observedCounts.length; i++) {
        	double diff = (double)observedCounts[i] - expectedCounts[i];
            double sq = (diff * diff) / expectedCounts[i];
    		//System.out.print("  diff   = " + observedCounts[i] + " - " + expectedCounts[i] + " = " + diff);
    		//System.out.print("  diff^2 = " + (diff * diff));
    		//System.out.println("  sq     = " + sq);
            chisq += sq;
        }
        return chisq;
    }
	
	/**
	 * Returns &chi;-square value given observed counts and expected counts.
	 * 
	 * @param observedCounts array of observed counts 
	 * @param expectedCounts array of expected counts
	 * @return &chi;-square value
	 */
    public static double chiSquare(int[] observedCounts, int[] expectedCounts) {
    	if(observedCounts.length != expectedCounts.length) {
    		System.out.println("Error: the lengths of arrays of observed and expected counts are different.");
    		System.exit(1);
    	}
    	double chisq = 0.0;
        for (int i = 0; i < observedCounts.length; i++) {
        	double diff = (double)observedCounts[i] - (double)expectedCounts[i];
            double sq = (diff * diff) / (double)expectedCounts[i];
    		//System.out.print("  diff   = " + observedCounts[i] + " - " + expectedCounts[i] + " = " + diff);
    		//System.out.print("  diff^2 = " + (diff * diff));
    		//System.out.println("  sq     = " + sq);
            chisq += sq;
        }
        return chisq;
    }

	////////////////////////////////////////////////////////////////
	// G statistics
	/**
	 * Returns G value given observed counts and expected counts.
	 * 
	 * @param observedCounts array of observed counts 
	 * @param expectedCounts array of expected counts
	 * @return G value
	 */
    public static double G(int[] observedCounts, double[] expectedCounts) {
    	if(observedCounts.length != expectedCounts.length) {
    		System.out.println("Error: the lengths of arrays of observed and expected counts are different.");
    		System.exit(1);
    	}
    	double sum = 0.0;
        for (int i = 0; i < observedCounts.length; i++) {
        	double KL = (double)observedCounts[i] * Math.log((double)observedCounts[i] / expectedCounts[i]);
            sum += KL;
        }
        return 2.0 * sum;
    }
    
    
	////////////////////////////////////////////////////////////////
	// Normal distribution
	/**
	 * Calculates the upper bound for a 95% confidence interval
	 * for a normal distribution with given mean and variance
	 * i.e., the value below which 97.5% of sample take.
	 * 
	 * @param mean mean
	 * @param variance variance
	 * @return the upper bound for a 95% confidence interval
	 */
	public static double upperBoundNormal95(double mean, double variance) {
		// x = mean+Z.Math.sqrt(variance) 
		//return mean+1.96*Math.sqrt(variance);
		return mean+1.959964*Math.sqrt(variance);
	}

	/**
	 * Calculates the upper bound for a 95% confidence interval
	 * for a normal distribution with given mean and variance, lower only
	 * i.e., the value below which 95% of sample take.
	 * 
	 * @param mean mean
	 * @param variance variance
	 * @return the upper bound for a (lower) 95% confidence interval
	 */
	public static double upperBoundNormal95Upper(double mean, double variance) {
		// x = mean+Z.Math.sqrt(variance) 
		//return mean+1.6449*Math.sqrt(variance);
		return mean+1.644854*Math.sqrt(variance);
	}
	
	/**
	 * Calculates the lower bound for a 95% confidence interval
	 * for a normal distribution with given mean and variance
	 * i.e., the value above which 97.5% of sample take.
	 * 
	 * @param mean mean
	 * @param variance variance
	 * @return the lower bound for a 95% confidence interval
	 */
	public static double lowerBoundNormal95(double mean, double variance) { 
		// x = mean-Z.Math.sqrt(variance)
		//return mean-1.96*Math.sqrt(variance);
		return mean-1.959964*Math.sqrt(variance);
	}

	/**
	 * Calculates the lower bound for a 95% confidence interval
	 * for a normal distribution with given mean and variance, upper only
	 * i.e., the value above which 95% of sample take.
	 * 
	 * @param mean mean
	 * @param variance variance
	 * @return the lower bound for a (upper) 95% confidence interval
	 */
	public static double lowerBoundNormal95Lower(double mean, double variance) { 
		// x = mean-Z.Math.sqrt(variance)
		//return mean-1.6449*Math.sqrt(variance);
		return mean-1.644854*Math.sqrt(variance);
	}
	

	/**
	 * Calculates the upper bound for zero information leakage.
	 * 
	 * @param freedom freedom
	 * @param sampleSize the number of samples
	 * @return upper bound for zero leakage
	 */
	public static double upperBoundForZero(int freedom, int sampleSize) {
		return Math.pow(InfoTheory.log2(Math.E),2)*chiSqu95Interval(freedom)/(2*sampleSize);
	}
	

	////////////////////////////////////////////////////////////////
	// Variance and standard dervation
    /*
     * Calculates the variance for an estimated non-zero capacity estimate.
     * <BR>
	 * variance equals 1/N.&Sigma;_i Q(i).(
	 *      (   ( &Sigma;_j W(j|i). (log( (Q(i).W(j|i)) / &Sigma;_{i'} Q(i').W(j|i')))^2)
     *        - (  (&Sigma;_j W(j|i).log( (Q(i).W(j|i)) / &Sigma;_{i'} Q(i').W(j|i')))^2) ) )
     * 
     * @param Q input PMF array
     * @param W channel matrix
     * @param sampleSize sample size
     * @return the variance for an estimated non-zero capacity estimate
     */
	/*
	public static double nonZeroVariance(double[] Q, double[][] W, int sampleSize) {
		double result = 0;
		for(int x = 0; x < W.length; x++) { //Sigma_i
			double firstPart = 0; // = ( \Sigma_j W(j|i). (log( (Q(i).W(j|i)) / Sigma_{i'} Q(i').W(j|i')))^2)
			double secondPart = 0; // =(\Sigma_j W(j|i).log( (Q(i).W(j|i)) / Sigma_{i'} Q(i').W(j|i')))^2
			
			for(int y = 0; y < (W[0]).length; y++) { //Sigma_j
				if(W[x][y] != 0)
					firstPart += W[x][y]*Math.pow(InfoTheory.log2( (Q[x]*W[x][y]) / InfoTheory.outputProb(y,Q,W)),2);
			}
			
			for(int y = 0; y < (W[0]).length; y++) { //Sigma_j
				if(W[x][y] != 0)
					secondPart += W[x][y]*InfoTheory.log2( (Q[x]*W[x][y]) / InfoTheory.outputProb(y,Q,W));
			}
			secondPart = Math.pow(secondPart, 2);
			
			result += Q[x]*(firstPart - secondPart);
		}
		return ((1/(double)sampleSize)*result)*Math.pow(InfoTheory.log2(Math.E),2);
	}
	*/


	/*
     * Calculates the variance for an estimated non-zero capacity estimate.
	 * 
	 * @param pd (prior) input probability distribution
	 * @param channel channel
     * @param sampleSize sample size
     * @return the variance for an estimated non-zero capacity estimate
	 */
	/*
	public static double nonZeroVariance(ProbDist pd, Channel channel, int sampleSize) {
		double[] pmf;
		if(pd != null)
			pmf = pd.probDistToPMFArray(channel.getInputNames());
		else
			pmf = ProbDist.uniformProbArray(channel.noOfInputs());
		double[][] matrix = channel.getMatrix();
		if(pmf != null)
			return nonZeroVariance(pmf, matrix, sampleSize);
		else
			return (double)ERROR;
	}
	*/


	/**
	 * Calculates the standard deviation for sampled data, using:
	 * <BR>
	 * s = sqrt( (Sigma_i (x_i - x)^2) / (n-1) )
	 * 
	 * @param data sampled data
	 * @param sum summation of the data
	 * @return standard deviation for sampled data
	 */
	public static double sdtDevSampled(double[] data, double sum) {
		double average = sum /((double)data.length);
		
		double sumDiffsSquares = 0;
		for(int i = 0; i < data.length; i++) {
			sumDiffsSquares += ((average-data[i])*(average-data[i]));
		}
		
		return (Math.sqrt(1.0 / ((double)data.length - 1) * sumDiffsSquares));
	}

	/**
	 * Calculates the standard deviation for sampled data.
	 * 
	 * @param data sampled data
	 * @return the standard deviation for sampled data
	 */
	public static double sdtDevSampled(double[] data) {
		double sum = 0;
		for(double value : data) {
			sum = sum +value;
		}
		return sdtDevSampled(data,sum);
	}

}
