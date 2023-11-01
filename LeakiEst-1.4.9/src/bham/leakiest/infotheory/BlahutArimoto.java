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
package bham.leakiest.infotheory;

import java.util.Arrays;
import bham.leakiest.Channel;

/**
 * This class calculates the capacity of a channel using the Blahut-Arimoto Algorithm.
 * The description for this algorithm is largely taken from the paper: "A Generalized
 * Blahut-Arimoto Algorithm" by Pascal Vontobel", N.B. this paper uses natural logs and
 * e where as we are using log2 and 2, to give the capacity in bit.
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @version 1.2.5
 */
public class BlahutArimoto {
	private boolean verbose = false;
	private boolean displayIts = false;

	private int noOfOutputs;
	private int noOfInputs;
	private String[] inputNames;
	private String[] outputNames;
	private double[][] channelMatrix_W;
	private double acceptableError;
	private int noOfiterations;
	private double[] inputPMF_Q;
	private Channel channel;
	
	private double capacity;
	private double possibleError;
	private int iteration = 1;
	
	/**
	 * Sets initial data to calculates the capacity. 
	 * 	
	 * @param channel channel
	 * @param inputPMF_Q input PMF array
	 * @param acceptableError acceptable error rate for the calculation of capacity
	 * @param noOfiterations the maximum number of iterations to calculate of capacity
	 */
	public BlahutArimoto(Channel channel, double[] inputPMF_Q, double acceptableError, int noOfiterations)	{
		this.inputNames = channel.getInputNames();
		this.outputNames = channel.getOutputNames();
		this.channelMatrix_W = channel.getMatrix();
		this.inputPMF_Q = inputPMF_Q;
		this.acceptableError = acceptableError;
		this.noOfiterations = noOfiterations;
		noOfInputs = inputNames.length; 
		noOfOutputs = outputNames.length;
		this.channel = channel;
	}
	
	/**
	 * Sets initial data to calculates the capacity. 
	 * 
	 * @param channel channel
	 * @param acceptableError acceptable error rate for the calculation of capacity
	 * @param noOfiterations the maximum number of iterations to calculate of capacity
	 */
	public BlahutArimoto(Channel channel, double acceptableError, int noOfiterations) {
		this.inputNames = channel.getInputNames();
		this.outputNames = channel.getOutputNames();
		this.channelMatrix_W = channel.getMatrix();
		this.inputPMF_Q = InfoTheory.uniformDist(inputNames.length);
		this.acceptableError = acceptableError;
		this.noOfiterations = noOfiterations;
		noOfInputs = inputNames.length; 
		noOfOutputs = outputNames.length;
		this.channel = channel;
	}

	/**
	 * Sets initial data to calculates the capacity. 
	 * 
	 * @param inputNames input names
	 * @param outputNames output names
	 * @param channelMatrix_W channel matrix
	 * @param inputPMF_Q input PMF array
	 * @param acceptableError acceptable error rate for the calculation of capacity
	 * @param noOfiterations the maximum number of iterations to calculate of capacity
	 */
	public BlahutArimoto( String[] inputNames,
						  String[] outputNames,
						  double[][] channelMatrix_W,
						  double[] inputPMF_Q,
						  double acceptableError,
						  int noOfiterations ) {
		this.inputNames = inputNames;
		this.outputNames = outputNames;
		this.channelMatrix_W = channelMatrix_W;
		this.inputPMF_Q = inputPMF_Q;
		this.acceptableError = acceptableError;
		this.noOfiterations = noOfiterations;
		noOfInputs = inputNames.length; 
		noOfOutputs = outputNames.length;
	}

	
	/**
 	 * Returns the capacity.
	 *
	 * @return capacity
	 */
	public double getCapacity() { return capacity; }

	/**
 	 * Returns the possible error of the result.
	 *
	 * @return possible error
	 */
	public double getPossibleError() { return possibleError; }

	/**
 	 * Returns the acceptable error of the result.
	 *
	 * @return acceptable error
	 */
	public double getAcceptableError() { return acceptableError; }

	/**
 	 * Returns the input distribution that achieves capacity.
	 *
	 * @return maximising input distribution
	 */
	public double[] getMaxInputDist() { return inputPMF_Q; }

	/**
 	 * Returns the number of iterations in Blahut-Arimoto algorithm.
	 *
	 * @return the number of iterations
	 */
	public int getIterationCount() { return iteration; }

	/**
 	 * Sets the value of verbose.
	 * @param b the value of verbose
	 */
	public void setVerbose(boolean b) { verbose = b;}

	/**
 	 * Calculates capacity.
	 *
	 * @return capacity
	 */
	public double calculateCapacity() {
		boolean finished = false;

		// We require that channelMatrix_W.length =  noInputs
		// and that channelMatrix_W[i].length  =  noOnputs for all i
		// Start off with a random inputPMF which will become 
		// closer to the real value with each iteration.
		// We require that inputPMF_Q.length = noInputs
		// inputPMF_Q = defaultInputPMF_Q; 
		
		double[] newInputPMF = new double[noOfInputs];	
			
		if(verbose && displayIts) { 
			System.out.println("\n Channel Matix is: \n"); 
			channel.printChannel();
		}
	
		while(iteration < noOfiterations && finished == false) {
			if(verbose  && displayIts) { 
				System.out.println("\n \nIteration "+iteration); 
				System.out.print("  Trying inputPMF_Q =    "); 
				InfoTheory.printPMF(inputNames,inputPMF_Q); 
			}
	//		System.out.print("\n  This inputPMF makes the probs of the outputs: "); 
	//		for(int i = 0; i < noOfOutputs; i++) {
	//			System.out.print(outputNames[i]+":"+ calculateOutputProb_R_QW(i,inputPMF_Q,channelMatrix_W)+", ");
	//		}
		
			possibleError = calculateError(inputPMF_Q,channelMatrix_W);
			if(verbose && displayIts)
				System.out.print("\n  Maximum possible error = "+ possibleError);
			//System.out.print("\n  Calculating next inputPMF:    ");
			//	
			for(int i = 0; i < noOfInputs; i++) {
				newInputPMF[i] = inc_2powerT(i, inputPMF_Q, channelMatrix_W) / sumOfTValues(inputPMF_Q, channelMatrix_W) ;	
				//System.out.print(inputNames[i]+":"+ newInputPMF[i]+", ");
			}
			
			capacity = ShannonEntropy.mutualInformation(inputPMF_Q,channelMatrix_W);
			if(verbose  && displayIts)
				System.out.println("\n  This input PMF give a Channel Capacity "+capacity);
			// System.out.println(" Entropy of new input pmf: "+ entropy_HX(newInputPMF));
			
			if( Arrays.equals(inputPMF_Q,newInputPMF) || possibleError <= acceptableError) { 
				finished = true;
			} else {
				System.arraycopy(newInputPMF, 0, inputPMF_Q, 0, noOfInputs);
				iteration++;
			}		
		}

		// zero error might appear non-zero due to rounding error in Java doubles
		if(finished && Arrays.equals(inputPMF_Q,newInputPMF))
			possibleError = 0;
		
		if(verbose) { 
			if( finished && (Arrays.equals(inputPMF_Q,newInputPMF) || possibleError==0) ) {
				System.out.println("\n\nComplete, after "+iteration+" iterations");
				//	System.out.println("  The Channel Capacity is: "+ IT.mutualInformation(newInputPMF,channelMatrix_W));
				System.out.println("  The attacker learns: "+ capacity  +" bit of information about the users");
				//System.out.println("  I.e. they learn the user's ID with probility:  "+(capacity / IT.log2(noOfInputs)));
				System.out.println("  Capacity/log2(inputs)} is "+ (capacity / InfoTheory.log2(noOfInputs))+" out of 1");
			} else {
				if(possibleError <= acceptableError) {
					System.out.println("\n\nCapacity calculated to within acceptable error, in "+iteration+" iterations");
				} else { 
					System.out.println("\n\nNOT COMPLETE\nPerformed the maximum number of iterations: "+iteration+"\n  The current results are:");
				}
				
				System.out.printf("  The Channel Capacity is: %1$6.5g +/- %2$6.5g\n",(capacity+(possibleError/2)),(possibleError/2));
				//System.out.println("  I.e. they learn the user's ID with around probability:  "+ (capacity / log2(noOfInputs)));
				System.out.println("  Capacity/2^{inputs} is "+ (capacity / InfoTheory.log2(noOfInputs))+" out of 1");
			}
		System.out.print("  Input distribution: ");
		InfoTheory.printPMF(inputNames,inputPMF_Q);
		}
		return capacity;
	}
	
	/*
	 * Returns 2^{Sigma_y W(y|x).log ( Q(x).W(y|x)/(QW)(y) )
     *      with the special cases that 0.log(0) = 0        (as x.log(x) -> 0 as x -> 0) 
	 *      and log (0/0) = 0                               (as x/x -> 1 as x -> 0 and log(1) = 0) 
	 *      and e^(...+ n.log 0 + ... ) = 0 went n != 0     (as n.log(x) -> -inf as x -> x)
	 *
	 * @param inputElement
	 * @param inputProbs_Q input PMF
	 * @param matrix_W channel matrix
	 * @return 
	 */
	private double inc_2powerT(int inputElement, double[] inputProbs_Q,double[][] matrix_W ){
		// We need to avoid taking the log of 0
		boolean minusinf = false; // set to true if we make n.log(0) at when summing T
		double sum = 0;
		double logtop,logbottom,W;
		int loopcounter = 0;
		
		while(loopcounter < noOfOutputs && !minusinf) {
            W = matrix_W[inputElement][loopcounter];
            logtop = (inputProbs_Q[inputElement] * matrix_W[inputElement][loopcounter]);
            logbottom =  InfoTheory.QW(loopcounter,inputProbs_Q,matrix_W);
  
            if(W != 0 && logtop != 0) {	// N.B. bottom == 0 => top == 0, so we never divide by zero
            	sum = sum + W * InfoTheory.log2 ( logtop/logbottom);
            } else if(W!=0 && logtop == 0 && logbottom !=0 ) {
            	// we are trying to calculate 2^(-inf) so set flag and stop the calculation, 
            	minusinf = true;
            }
            // The other cases have no effect on the result
            //    W == 0  => terms is 0.log(0) = 0
            //    W != 0 && logtop == 0 && logbottom == 0 => term is n.log(0/0) = 0
            //    W != 0 && logtop != 0 && logbottom == 0 can't happen as  logbottom == 0 => logtop != 0
            loopcounter++;
		}
		
		if(minusinf)
			return 0;
		else
			return Math.pow(2,sum);
	}
	
	/**
	 * Finds the maximum possible error for a input PMF using:
	 * <BR>
	 * I(Q,W) &le; true Cap &le; max_x[T(x) -log(Q(x))]
	 * i.e. max possible err is max_x[T(x) -log(Q(x))] - I(Q,W).
	 * <BR>
	 * Find max_x[T(x) -log(Q(x))] where
	 * <BR>
	 *      T(x) =  Sigma_y W(y|x).log(Q(x).W(y|x) / (QW)(y))
	 * <BR>
	 *	    we take log (0/0) = 0  (as x/x &rarr; 1 as x &rarr; 0 and log(1) = 0) 
	 *	    and n.log 0 = -inf     (as n.log(x) &rarr; -inf as x &rarr; x)
	 * 
	 * @param inputProbs_Q input PMF
	 * @param matrix_W channel matrix
	 * @return the maximum possible error
	 */
	public double calculateError(double[] inputProbs_Q, double[][] matrix_W ) {
		double T;
		double maxTminuslogQ = 0;
		boolean maxTminuslogQSet = false;
		for(int u = 0; u < noOfInputs; u++) {
			if(inputProbs_Q[u] != 0 ) {
				// Find T(x)	
				T = 0;
				for(int y = 0; y < noOfOutputs; y++) {
					if(matrix_W[u][y]!=0) {	
					    // Q(x)!=0=!W  =>  W,logtop,logbottom != 0  (so we're not dividing by 0)
						T = T + matrix_W[u][y] * InfoTheory.log2 ( (inputProbs_Q[u] * matrix_W[u][y])
						                                /InfoTheory.QW(y,inputProbs_Q,matrix_W));  
					}
					// W == 0 case results in W(y|x).log(Q(x).W(y|x) / (QW)(y)) = 0
					// Q(x) != means that minusinf case can't happen.
		        }
				if(maxTminuslogQSet) {
					maxTminuslogQ = Math.max(maxTminuslogQ, (T-InfoTheory.log2(inputProbs_Q[u])) );	
				} else {
					maxTminuslogQ = T - InfoTheory.log2(inputProbs_Q[u]);
					maxTminuslogQSet = true;
				}
			}
		}		
		return maxTminuslogQ - ShannonEntropy.mutualInformation(inputProbs_Q,matrix_W);
	}
	
	
	/*
	 * Calculates Sigma_x e^{T(x)} 
	 * 	
	 * @param inputProbs_Q input PMF
	 * @param matrix_W channel matrix
	 * @return Sigma_x e^{T(x)}
	 */
	private double sumOfTValues(double[] inputProbs_Q, double[][] matrix_W ) {
		double result = 0;
		
		for(int i = 0; i < noOfInputs; i++) {
			// if p(x) = 0 then 2^{T(x)} should equal 0 (???)
			if(inputProbs_Q[i] != 0) { 
				result += inc_2powerT(i, inputProbs_Q, matrix_W );
			}
		}
		return result;
	}
}
