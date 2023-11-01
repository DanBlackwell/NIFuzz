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
 * Copyright 2014 Tom Chothia and Yusuke Kawamoto
 */
package bham.leakiest.infotheory;

import java.util.Arrays;
import bham.leakiest.*;

/**
 * This is a library of useful information theory definitions. Most are 
 * complete standard, see for example "Elements of Information Theory" 
 * by Cover and Thomas. <br>
 *
 * Probability Mass Functions are represented by an array of doubles
 * p(element i) = pmf[i] or by ProbDist class. <br>
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @version 1.4.5
 */
public class InfoTheory {
	// Verbose
	static int verbose = TestInfoLeak.verbose;

	/**
	 * Base when computing the logarithms.
	 */
	public static final int base_log = 2;
	static final int ERROR = -1;
	
	/**
	 * Calculates the logarithm of input x w.r.t any base.
	 * 
	 * @param x the real number whose logarithm is calculated.
	 * @param base The base w.r.t. which logarithm is calculated.
	 * @return the logarithm of input x w.r.t base.
	 */
	public static double log(double x, int base) {
	    //if(x == 0) 
	    	//return 0;
		//else 
			return Math.log(x) / Math.log(base);
	}

	/**
	 * Calculates the logarithm of input x w.r.t base 2.
	 * 
	 * @param x the real number whose logarithm is calculated.  
	 * @return the logarithm of input x w.r.t base 2.
	 */
	public static double log2(double x) {
		return log(x, 2);
	}

	/**
	 * Calculates the logarithm of input x w.r.t any base,
	 * multiplied by y, where 0 log 0 = 0.
	 * 
	 * @param x the real number whose logarithm is calculated.
	 * @param base the base w.r.t. which logarithm is calculated.
	 * @param y the real number that multiplies log_{base} x
	 * @return the logarithm of input x w.r.t base.
	 */
	public static double logMulti(double x, int base, double y) {
	    if(y == 0)
	    	return 0;
		else 
			return Math.log(x) / Math.log(base);
	}

	/**
	 * Calculates the logarithm of input x w.r.t base 2,
	 * multiplied by y, where 0 log 0 = 0.
	 * 
	 * @param x the real number whose logarithm is calculated.  
	 * @param y the real number that multiplies log_2 x
	 * @return the logarithm of input x w.r.t base 2.
	 */
	public static double log2Multi(double x, double y) {
		return logMulti(x, 2, y);
	}

	/**
	 * This method returns the mean of given data.
	 * 
	 * @param Data data array
	 * @return the mean of the data
	 */
	public static double mean(double[] Data) {
		double Total = 0.0;
		for(double d : Data) {
			Total += d;
		}
		return Total / (double)Data.length;
	}

	/**
	 * This method returns the median of given data.
	 * 
	 * @param Data data array
	 * @return the median of the data 
	 */
	public static double median(double[] Data) {
		double[] DataSorted = new double[Data.length];
		System.arraycopy(Data, 0, DataSorted, 0, Data.length);
		Arrays.sort(DataSorted);
		if(Data.length % 2 == 0) {
			return (double)DataSorted[Data.length/2];
		} else {
			return ((double)DataSorted[Data.length/2] +
				    (double)DataSorted[Data.length/2 + 1]) / 2;
		}	
	}
	
	/*
	 * variance equals 1/N.&Sigma;_i Q(i).(
	 *   (   ( &Sigma;_j W(j|i). (log( (Q(i).W(j|i)) / &Sigma;_{i'} Q(i').W(j|i')))^2)
     *     - (  (&Sigma;_j W(j|i).log( (Q(i).W(j|i)) / &Sigma;_{i'} Q(i').W(j|i')))^2) ) )
	 * @param sampleSize the number of samples
	 * @param Q input PMF array
	 * @param W channel matrix
	 * @return Variance variance 
	 */
	/*
	private static double variance(int sampleSize, double[] Q, double[][] W) {
		double result = 0;
		for(int x = 0; x < W.length; x++) { //Sigma_i
			double firstPart = 0; // = (\Sigma_j W(j|i).(log( (Q(i).W(j|i)) / Sigma_{i'} Q(i').W(j|i')))^2)
			double secondPart = 0; // =(\Sigma_j W(j|i).log( (Q(i).W(j|i)) / Sigma_{i'} Q(i').W(j|i')))^2
			
			for(int y = 0; y < (W[0]).length; y++) //Sigma_j
				firstPart = firstPart + W[x][y]*Math.pow(log( (Q[x]*W[x][y]) / QW(y,Q,W), base_log),2);
			
			for(int y = 0; y < (W[0]).length; y++) //Sigma_j
				secondPart = secondPart + W[x][y]*log( (Q[x]*W[x][y]) / QW(y,Q,W), base_log);

			secondPart = Math.pow(secondPart, 2);
			result += Q[x] * (firstPart - secondPart);
		}
		return ((1 / (double)sampleSize) * result);
	}
	*/

	/**
	 * Calculate the marginal output probability distribution
	 * P_Y from a given input distribution inputDist and
	 * a given channel matrix matrix.
	 * 
	 * @param inputDist input distribution array
	 * @param matrix channel matrix array
	 * @return the marginal output probability distribution
	 */
	public static double[] outputDist(double[] inputDist, double[][] matrix) {
		//double sum = 0;
		double outputdist[] = new double[matrix[0].length];
		for(int j = 0; j < matrix[0].length; j++) {
			outputdist[j] = 0;
			for(int i = 0; i < matrix.length; i++) {
				outputdist[j] += inputDist[i] * matrix[i][j];
			}
			//System.out.println("outputdist[" + j + "] = " + outputdist[j]);
			//sum += outputdist[j];
		}
		//System.out.println("sum = " + sum);
		return outputdist;
	}

	/**
	 * Finds the change of output elementIndex
	 * using P_Y(y) = R(y) = QW(y) = &Sigma;_x W(y|x)Q(x).
	 * 
	 * @param outputIndex output index of the channel matrix W
	 * @param Q input PMF array
	 * @param W channel matrix
	 * @return the sum of joint probability for outputIndex
	 */
	public static double outputProb(int outputIndex, double[] Q, double[][] W)	{
		double result = 0;	
		for(int i = 0; i < Q.length; i++)
			result = result + W[i][outputIndex] * Q[i];
		return result;
	}
	
	/*
	 * Finds the change of output elementIndex
	 * using P_Y(y) = QW(y) = &Sigma;_x W(y|x)Q(x).
	 * Produces the same result as outputProb(int outputIndex, double[] Q, double[][] W).
	 * 
	 * @param outputIndex output index of the channel matrix W
	 * @param inputProbs_Q input PMF array
	 * @param matrix_W channel matrix
	 * @return the sum of joint probability for outputIndex
	 */
	private static double R(int outputIndex, double[] inputProbs_Q, double[][] matrix_W ) {
		return  outputProb(outputIndex, inputProbs_Q, matrix_W);
	}

	/*
	 * Finds the change of output elementIndex
	 * using P_Y(y) = QW(y) = &Sigma;_x W(y|x)Q(x).
	 * Produces the same result as outputProb(int outputIndex, double[] Q, double[][] W).
	 * 
	 * @param outputIndex output index of the channel matrix W
	 * @param inputProbs_Q input PMF array
	 * @param matrix_W channel matrix
	 * @return the sum of joint probability for outputIndex
	 */
	protected static double QW(int outputIndex, double[] inputProbs_Q, double[][] matrix_W ) {
		return  outputProb(outputIndex, inputProbs_Q, matrix_W);
	}

	/**
	 * Calculates the uniform distribution of length "noOfElements".
	 * 
	 * @param noOfElements the number of elements in the uniform distribution.
	 * @return the uniform distribution of length "noOfElements".
	 */
	public static double[] uniformDist(int noOfElements) {
		double[] dist = new double[noOfElements];
		for(int i = 0; i < noOfElements; i++)
			dist[i] = 1.0 /(double)noOfElements;
		return dist;
	}


	////////////////////////////////////////////////////
	// Print functions for probability mass functions //
	/**
	 * Prints the probability distribution probs with
	 * where element a_i has prob[i], to 4 decimal places.
	 * 
	 * @param probs array of PMF
	 */
	public static void printPMF(double[] probs)	{
		// Require that names.length = probs.length > 1
		System.out.printf(", a0: %6.5f",probs[0]);
		for(int i = 1; i < probs.length; i++) {
			System.out.printf(", a"+i+": %6.5f",probs[i]);
		}
	}
	
	/**
	 * Prints the probability distribution probs with
	 * where element names[i] has prob[i].
	 * 
	 * @param names array of labels
	 * @param probs array of PMF
	 */
	public static void printPMF(String[] names, double[] probs)	{
		// Require that names.length = probs.length > 1
		System.out.printf("  [ " + names[0]+": %6.4f",probs[0]);
		for(int i = 1; i < names.length; i++) {
			System.out.printf(", "+names[i]+": %6.4f",probs[i]);
		}
		System.out.print(" ]");
	}
	
}
