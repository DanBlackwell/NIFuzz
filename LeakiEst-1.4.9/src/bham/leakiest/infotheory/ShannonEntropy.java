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

import bham.leakiest.*;

/**
 * This is a library of useful information theory definitions related
 * to Shanon-entropy-based information measure. <br>
 *
 * Probability Mass Functions are represented by an array of doubles
 * p(element i) = pmf[i] or by ProbDist class. <br>
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @version 1.4
 */
public class ShannonEntropy {
	// Verbose
	private static int verbose = TestInfoLeak.verbose;

	/**
	 * Base when computing the logarithms.
	 */
	public static final int base_log = 2;
	private static final int ERROR = -1;


	///////////////////////////////////////////////////////////////////
	// Calculation of entropy, conditional entropy and joint entropy //
	/**
	 * Calculates the entropy of a PMF array.
	 * @param pmf PMF array
	 * @return the entropy of pmf
	 */
	public static double entropy(double[] pmf) {
		double result = 0; 
		for(int i = 0; i < pmf.length; i++) {
			// Entropy calculation requires that 0 * log(0) = 0
			if(pmf[i] != 0)
				result += pmf[i] * InfoTheory.log(pmf[i], InfoTheory.base_log);
		}
		return - result;
	}


	/**
	 * Calculates the entropy of a probability distribution.
	 * @param pd probability distribution
	 * @return the entropy of pd
	 */
	public static double entropy(ProbDist pd) {
		double result = 0; 
		for(State st : pd.getStatesCollection()) {
			double prob = pd.getProb(st);
			// Entropy calculation requires that 0 * log(0) = 0
			if(prob != 0)
				result += prob * InfoTheory.log(prob, InfoTheory.base_log);
		}
		return - result;
	}


	/**
	 * Calculates the entropy of a PMF array.
	 * @param pmf PMF array
	 * @return the entropy of pmf
	 */
	public static double H(double[] pmf) {
		return entropy(pmf);
	}


	/**
	 * Calculates the entropy of a probability distribution.
	 * @param pd probability distribution
	 * @return the entropy of pd
	 */
	public static double H(ProbDist pd) {
		return entropy(pd);
	}


	/**
	 * Calculates the conditional entropy of a channel matrix
	 * given an input PMF.
	 * <BR>
	 * N.B. the inputs to this function are a PMF and a Channel Matrix
	 * that links that PMF with the other PMF  i.e., X and the channel to Y
	 * The inputs are NOT two pmfs i.e., H(Q,W) not H(X|Y)
	 * matrix_W[input][output] = W(output|input).
	 * @param pmf PMF array
	 * @param matrix_W channel matrix array
	 * @return the conditional entropy of matrix_W given pmf
	 */
	public static double conditionalEntropy(double[] pmf, double[][] matrix_W) {
		// This method returns H(X|Y) where X is given by pmf and matrix_W is the channel from X to Y  
		//  i.e. value returned equals: - Sigma_x Q(x).Sigma_y W(y|x).log( Q(x).W(y|x)/(QW)(y) )
		//                            = - Sigma_x.Sigma_y Q(x).W(y|x).log( Q(x).W(y|x)/(QW)(y) )
		//  QW(y) = 0 => Q(x).W(y|x) = 0 therefore 
		//        if Q(x).W(y|x) = 0 we take W(y|x).log( Q(x).W(y|x)/(QW)(y) ) = 0MIuniformInput
	
		double result = 0; 
		//Sigma_x
		for(int i = 0; i < pmf.length; i++) {
			for(int j = 0; j < matrix_W[0].length; j++) {
				if(pmf[i] != 0 && matrix_W[i][j] != 0) {
					result = result
						   + pmf[i] * matrix_W[i][j] 
					         * InfoTheory.log( (pmf[i] * matrix_W[i][j] ) / InfoTheory.QW(j,pmf,matrix_W), InfoTheory.base_log);
				}
			}
		}
		return (-result);
	}


	/**
	 * Calculates the conditional entropy of a channel matrix
	 * given an input PMF.
	 * Produces the same result as conditionalEntropy(double[] pmf, double[][] matrix_W).
	 *  
	 * @param pmf PMF array
	 * @param W channel matrix array
	 * @return the conditional entropy of W given pmf
	 */
	public static double H(double[] pmf, double[][] W) {
		return conditionalEntropy(pmf, W);
	}

	/**
	 * Calculates the conditional entropy of a channel 
	 * given an input probability distribution.
	 * 
	 * @param pd input probability distribution
	 * @param channel channel
	 * @return the conditional entropy of channel given pd
	 */
	public static double conditionalEntropy(ProbDist pd, Channel channel) {
		double[] pmf = pd.probDistToPMFArray(channel.getInputNames());
		double[][] W = channel.getMatrix();
		if(pmf != null)
			return conditionalEntropy(pmf, W);
		else
			return (double)InfoTheory.ERROR;
	}

	/**
	 * Calculates the conditional entropy of a channel 
	 * given an input probability distribution.
	 * Produces the same result as conditionalEntropy(ProbDist pd, Channel channel).
	 * 
	 * @param pd input probability distribution
	 * @param channel channel
	 * @return the conditional entropy of channel given pd
	 */
	public static double H(ProbDist pd, Channel channel) {
		return conditionalEntropy(pd, channel);
	}

	/**
	 * Calculates the joint entropy of X and Y
	 * where p(x,y) = p[x_index][y_index].
	 * <BR>
	 * H( (X,Y) ) = - &Sigma;_x &Sigma;_y p(x,y).log(p(x,y)) 
	 * 
	 * @param p the joint probability of X and Y
	 * @return the joint entropy of X a d Y
	 */
	public static double jointEntropy(double[][] p) {
		double result = 0;
		for(int x = 0; x < p.length; x++) {
			for(int y = 0; y < p[0].length; y++) {
				if(p[x][y] != 0)
					result += p[x][y]*InfoTheory.log(p[x][y], InfoTheory.base_log);
			}
		}
		return -result;
	}


	///////////////////////////////////////
	// Calculation of mutual information //
	/**
	 * Calculates mutual information between
	 * an input PMF and a channel matrix.
	 * <BR>
	 * N.B. the inputs to this function are a PMF and a Channel Matrix
	 * that links that PMF with the other PMF  i.e., X and the channel to Y.
	 * The inputs are NOT two pmfs i.e., I(Q,W) not I(X;Y).
	 * <BR>
	 * This method returns I(Q,W) = I(X;Y) = H(X) - H(X|Y).
	 * 
	 * @param Q input PMF array
	 * @param W channel matrix
	 * @return mutual information between Q and W 
	 */
	public static double mutualInformation(double[] Q, double[][] W) {
		return ( H(Q) - conditionalEntropy(Q,W) );
	}

	/**
	 * Calculates mutual information between
	 * an input PMF and a channel matrix.
	 * Produces the same result as mutualInformation(double[] Q, double[][] W).
	 * 
	 * @param Q input PMF array
	 * @param W channel matrix
	 * @return the mutual information between Q and W
	 */
	public static double I(double[] Q, double[][] W) {
		return mutualInformation(Q,W);
	}

	/**
	 * Calculates mutual information between
	 * an input PMF and a channel matrix.
	 * 
	 * @param pd input probability distribution
	 * @param channel channel
	 * @return the mutual information between pd and channel
	 */
	public static double mutualInformation(ProbDist pd, Channel channel) {
		double[] Q = pd.probDistToPMFArray(channel.getInputNames());
		double[][] W = channel.getMatrix();
		if(Q != null)
			return mutualInformation(Q,W);
		else
			return (double)InfoTheory.ERROR;
	}

	/**
	 * Calculates mutual information between
	 * an input PMF and a channel matrix.
	 * Produces the same result as mutualInformation(ProbDist pd, Channel channel).
	 * 
	 * @param pd input probability distribution
	 * @param channel channel
	 * @return the mutual information between pd and channel
	 */
	public static double I(ProbDist pd, Channel channel) {
		return mutualInformation(pd,channel);
	}

	/**
	 * Calculates the mutual information given an uniform input distribution.
	 * @param W channel matrix
	 * @return The mutual information 
	 */
	public static double MIuniformInput(double[][] W) {
		return mutualInformation(InfoTheory.uniformDist(W.length),W);
	}


	/////////////////////////////////////
	// Calculation of relative entropy //
	/**
	 * Calculates the relative entropy of two PMFs p and q.
	 * <BR>
	 * D(p||q) = &Sigma;_x p(x) log(p(x)/q(x))
	 * <BR>
	 * 0.log(0/q) = 0  and 
	 * p.log(p/0) = inf, (we throw an exception rather that return inf)
	 * 
	 * @param p PMF array
	 * @param q PMF array
	 * @return the relative entropy of two PMFs p and q
	 * @throws ArithmeticException Exception occured by division by zero
	 */
	public static double relativeEntropy(double[] p, double[] q) throws ArithmeticException	{
		double result = 0;
		for(int x = 0; x < p.length; x++) {
			if(p[x] != 0) {
				if(q[x] == 0)
					throw new ArithmeticException ("The Relative Entropy equals infinite");
				else 
					result += p[x] * InfoTheory.log(p[x]/q[x], InfoTheory.base_log);
			}
		}
		return result;
	}


	/**
	 * Calculates the relative entropy of two PMFs p and q.
	 * Produces the same result as relativeEntropy(double[] p, double[] q).
	 * 
	 * @param p PMF array
	 * @param q PMF array
	 * @return the relative entropy of two PMFs p and q
	 * @throws ArithmeticException Exception occured by division by zero
	 */
	public static double D(double[] p, double[] q) throws ArithmeticException {
		return relativeEntropy(p,q);
	}


	/**
	 * Calculates the relative entropy of two PMFs p and q.
	 * Produces the same result as relativeEntropy(double[] p, double[] q).
	 * 
	 * @param p PMF array
	 * @param q PMF array
	 * @return the relative entropy of two PMFs p and q
	 * @throws ArithmeticException Exception occured by division by zero
	 */
	public static double KullbackLeibler(double[] p, double[] q) throws ArithmeticException	{ 
		return relativeEntropy(p,q);
	}
	
}
