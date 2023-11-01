package bham.leakiest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import bham.leakiest.comparator.ComparatorStringWithInt;
import bham.leakiest.comparator.Pair;
import bham.leakiest.infotheory.BlahutArimoto;
import bham.leakiest.infotheory.GLeakage;
import bham.leakiest.infotheory.GainFunction;
import bham.leakiest.infotheory.InfoTheory;
import bham.leakiest.infotheory.KernelFunction;
import bham.leakiest.infotheory.MinEntropy;
import bham.leakiest.infotheory.ShannonEntropy;

/**
 * This is the class for printing leakage values.
 *
 * @author Yusuke Kawamoto
 * @author Tom Chothia
 * @author Chris Novakovic
 * @version 1.4.9
 */
public class PrintLeakageValue {
	private ArrayList<Double> leakage = new ArrayList<Double>();
	private ArrayList<Double> zeroLimit = new ArrayList<Double>();
	private ArrayList<Double> lowerLimit = new ArrayList<Double>();
	private ArrayList<Double> upperLimit = new ArrayList<Double>();
	private ArrayList<String> confidence = new ArrayList<String>();
	private static double[] inputDist;

	private boolean PRINT_CHANNELMATRIX = false;
	private boolean PRINT_JOINTMATRIX = false;
	private int verbose = 0;
	private double acceptableError = 0.000000000001;
	private int noOfIterations = 10000;
	private boolean OBS_DISCRETE = true;
	private boolean readFromChanFile = false;
	
	private boolean priorNonUniform = false;
	private boolean checkEachFeature = false;
	private boolean skipZLT = false;
	private boolean correctLeak = true;
	private boolean correctLeakNew = true;
	
	// Constants on task types
	static final int CLC_MUTUAL_INFO = 1;
	static final int CLC_CAPACITY = 2;
	static final int CLC_MIN_ENTROPY = 3;
	static final int CLC_MIN_CAPACITY = 4;
	static final int CLC_G_LEAK = 5;
	
	// Other constants
	static final double ERROR = -1;
	static final double UNKNOWN = -2;
	static final double APPROX_OPTIMIZED = 10.0;
	
	public PrintLeakageValue(boolean PRINT_CHANNELMATRIXin, boolean PRINT_JOINTMATRIXin, int verboseIn, double acceptableErrorIn, int noOfIterationsIn, boolean OBS_DISCRETEin, boolean readFromChanFileIn, boolean skipZLTin, boolean correctLeakIn, boolean correctLeakNewIn) {
		this.PRINT_CHANNELMATRIX = PRINT_CHANNELMATRIXin;
		this.PRINT_JOINTMATRIX = PRINT_JOINTMATRIXin;
		this.verbose = verboseIn;
		this.acceptableError = acceptableErrorIn;
		this.noOfIterations = noOfIterationsIn;
		//this.noOfTestsContinuous = noOfTestsContinuousIn;
		this.OBS_DISCRETE = OBS_DISCRETEin;
		this.readFromChanFile = readFromChanFileIn;
		this.skipZLT = skipZLTin;
		this.correctLeak = correctLeakIn;
		this.correctLeakNew = correctLeakNewIn;
	}
	
	
	////////////////////////////
	////// Leakage print functions /////
	/*
	 * Chooses to calculate and print one of leakage measures
	 * in the case of discrete inputs.
	 * 
	 * @param taskType type of calculation of a leakage measure
	 * @param pd input probability distribution
	 * @param channel channel
	 * @param obs observations
	 * @param priorNonUniform whether or not the prior is non-uniform
	 * @param checkEachFeatureIn whether or not we print the result for each feature
	 */
	protected void printMeasure(int taskType, ProbDist pd, Channel channel, Observations obs, boolean priorNonUniformIn, boolean checkEachFeatureIn) {
		this.priorNonUniform = priorNonUniformIn;
		this.checkEachFeature = checkEachFeatureIn;
		int sampleSize = 0;
		if(obs != null) {
			sampleSize = obs.getSampleCount();
		}
		
		// print the channel matrix
		if(PRINT_CHANNELMATRIX) {
			channel.printChannel();
			// Print the numbers of inputs, outputs and samples
			if(verbose > 3) {
				System.out.println(channel.noOfInputs() + " inputs, " +
								   channel.noOfOutputs() + " outputs and " + sampleSize + " samples.\n");
			}
		}

		// print the joint matrix
		if(PRINT_JOINTMATRIX) {
			if(readFromChanFile) {
				channel.printJointMatrix(pd);
			} else {
				if(obs != null) {
					obs.printJointFrequencyMatrix();
				}
			}
			// Print the numbers of inputs, outputs and samples
			if(verbose > 3) {
				System.out.println(channel.noOfInputs() + " inputs, " +
								   channel.noOfOutputs() + " outputs and " + sampleSize + " samples.\n");
			}
		}
		
		// Switch on the kind of the task
		switch(taskType) {
		case(CLC_MUTUAL_INFO):
			if(correctLeak) {
				printDiscreteCorrectedMI(pd, channel, sampleSize);
			} else {
				printDiscreteNonCorrectedMI(pd, channel);
			}
			break;
		case(CLC_CAPACITY):
			if(correctLeak) {
				printDiscreteCorrectedChannelCapacity(channel, sampleSize);
			} else {
				printDiscreteNonCorrectedChannelCapacity(channel);
			}
			break;
		case(CLC_MIN_ENTROPY):
			if(correctLeak) {
				if(correctLeakNew) {
					if(verbose >= 1) {
						System.out.println("The confidence interval estimation is based on Chi-square test...");
					}
					printDiscreteMinEntropyLeakWithNewInterval(pd, channel, sampleSize, obs); // new method
				} else {
					if(verbose >= 1) {
						System.out.println("The confidence interval estimation is based on [Vajda'02] & [Dutta, Goswami'10].");
					}
					int[] sampleSizeGivenOutput = obs.getSampleCountGivenOutput();
					printDiscreteMinEntropyLeakWithInterval(pd, channel, sampleSize, sampleSizeGivenOutput); //old method
				}
			} else {
				printDiscreteMinEntropyLeakOnly(pd, channel);
			}
			break;
		case(CLC_MIN_CAPACITY):
			printDiscreteMinCapacity(channel);
			break;
		case(CLC_G_LEAK):
			//TODO: Complete here!!
			printDiscreteGLeakageOnly(pd, channel, TestInfoLeak.gf, TestInfoLeak.guessDomain);
			break;
		/*
		// The channel has multiple users that can send at the same time
		// so we use network information theory to find the worst case
		case (Channel.MULTI):
			multiChannelToCapacity(channel);
			break;
		case(Channel.COND):
			condChannelToCapacity(channel);
			break;
		*/
		}
		if(!checkEachFeature && verbose > 1)
			System.out.println("");
	}


	/*
	 * Chooses to calculate and print mutual information with uniform
	 * distribution in the continuous case.
	 * (Only mutual information is implemented.)
	 * 
	 * @param taskType type of calculation of a leakage measure
	 * @param cdata continuous data
	 * @param priorNonUniform whether the prior is non-uniform or not
	 * @param checkEachFeatureIn whether or not we print the result for each feature
	 */
	protected void printMeasure(int taskType, ContinuousData cdata, boolean priorNonUniformIn, boolean checkEachFeatureIn) {
		this.priorNonUniform = priorNonUniformIn;
		this.checkEachFeature = checkEachFeatureIn;

		switch(taskType) {
		case(CLC_MUTUAL_INFO):
			printContinuousMutualInformation(cdata);
			break;
		/*
		case(CLC_CAPACITY):
			printContinuousCapacity(cdata);
			break;
		case(CLC_MIN_ENTROPY):
			printContinuousMinEntropyLeak(cdata);
			break;
		case(CLC_MIN_CAPACITY):
			printContinuousMinCapacity(cdata);
			break;
		*/
		}
		if(!checkEachFeature || verbose > 1)
			System.out.println("");
	}


	/*
	 * Calculates and prints the mutual information for discrete observation (without correction). 
	 * 
	 * @param pd input probability distribution
	 * @param channel channel
	 */
	private void printDiscreteNonCorrectedMI(ProbDist pd, Channel channel) {
		double result;
		if(priorNonUniform) {
			result = ShannonEntropy.mutualInformation(pd, channel);
			System.out.printf("Mutual information: %1$6.4g \n", result);
		} else {
			result = ShannonEntropy.MIuniformInput(channel.getMatrix());
			System.out.printf("Mutual information: %1$6.4g  ", result);
			System.out.println(" Calculated with the uniform input distribution.");
		}
		if(result <= -1) {
			System.out.printf("Error: Failed to calculate mutual information.");
			return;
		}
		
		// Print conclusion on leakage
		System.out.printf("The attacker learns %6.4g bits", result);
		if(priorNonUniform) {
			System.out.printf(", out of a possible %6.4g bits, about the input events.", ShannonEntropy.entropy(pd));
		} else {
			System.out.printf(", out of a possible %6.4g bits, about the input events.", InfoTheory.log2(channel.noOfInputs()));
		}
		System.out.println();
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(ERROR);
		upperLimit.add(ERROR);
		confidence.add("NOT SURE   ");
	}


    /*
     * Calculates and prints the confidence of the estimated corrected mutual information.
     * 
	 * @param pd input probability distribution
	 * @param channel channel
	 * @param sampleSize sample size
     */
	private void printDiscreteCorrectedMI(ProbDist pd, Channel channel, int sampleSize) {
		double result;
		if(priorNonUniform) {
			result = ShannonEntropy.mutualInformation(pd, channel);
		} else {
			result = ShannonEntropy.MIuniformInput(channel.getMatrix());
		}
		if(result <= -1) {
			System.out.printf("Error: Failed to calculate mutual information.");
			return;
		}
		
		double correction = (double)(channel.noOfInputs()-1)*(double)(channel.noOfOutputs()-1)
						  / (double)(2*sampleSize)*InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);

		if(!checkEachFeature || verbose > 1) {
			System.out.print("Estimated mutual information: ");
			System.out.print(Stats.round(mean,4));
			if(priorNonUniform) {
				System.out.printf(" (out of possible %6.4g bits)\n", ShannonEntropy.entropy(pd));
			} else {
				System.out.printf(" (out of possible %6.4g bits)\n", InfoTheory.log2(channel.noOfInputs()));
			}
			if(!(priorNonUniform)) {
				System.out.println("  Calculated with the uniform input distribution.");
			}
			if(verbose > 2) {
				System.out.println("  noOfInputs: " + channel.noOfInputs() +
								   "  noOfOutputs " + channel.noOfOutputs());
			}
		}
		
		if( (channel.noOfInputs() <= 1) || channel.noOfOutputs() <= 1 ) {
			if(!checkEachFeature || verbose > 1) {
				System.out.println("It is impossible to calculate zero information leakage.");
			}
			if(verbose > 2) {
				System.out.println("  The numbers of inputs =  " + channel.noOfInputs());
				System.out.println("  The numbers of outputs = " + channel.noOfOutputs());
				System.out.println("  These values must not be 1.");
			}
			leakage.add(mean);
			zeroLimit.add(ERROR);
			lowerLimit.add(ERROR);
			upperLimit.add(ERROR);
			confidence.add("NOT SURE   ");
		} else {
			double zeroUpperBound = Stats.upperBoundForZero( (channel.noOfInputs()-1)*(channel.noOfOutputs()-1), sampleSize ); 
			double variance = Estimate.VarianceOfEstimatedMIUnderEstimatedPrior(pd, channel, sampleSize);
			double lower = Stats.round(Math.max(0.0, Stats.lowerBoundNormal95(mean, variance)),4);
			double upper = Stats.round(Stats.upperBoundNormal95(mean, variance),4);
			
			//Print the output, depending on the value of verbose
			//the higher "verbose" the more details given.
			if(verbose > 2) {
				System.out.println("  Correction = log_2(e).(noOfInputs-1)(noOfOutputs-1)/2.sampleSize = " +
									Stats.round(correction,4));
				//System.out.println("   The results are no more accurate that the correction value,");
				//System.out.println("   increase the sample size to decrease the correction.");
				System.out.printf("  Mean:     " + Stats.round(mean,4) + " (= "
								  + Stats.round(result,4) + " - " + Stats.round(correction, 4) + ")\n");
				System.out.printf("  Variance: %1$6.4g \n", variance);
			}
			
			if(!checkEachFeature || verbose > 1) {
				System.out.println("  Between " + lower + " and " + upper + " with 95% confidence");
				System.out.println("  With 95% confidence, if leakage (w/o correction) < " + Stats.round(zeroUpperBound,4) + ", we may consider no information is leaked.");

				if(result <= zeroUpperBound) {
					System.out.println("No leak detected.");
				} else {
					System.out.println("There is a leak.");
				}
			}
			
			leakage.add(mean);
			zeroLimit.add(zeroUpperBound);
			lowerLimit.add(lower);
			upperLimit.add(upper);
			if(zeroUpperBound == ERROR)
				confidence.add("NOT SURE   ");
			else {
				if(result <= zeroUpperBound)
					confidence.add("ZERO LEAK  ");
				else
					confidence.add("LEAK       ");
			}
		}
	}


	/*
	 * Calculates and prints the capacity for discrete observation (without correction).
	 * 
	 * @param channel channel
	 */
	private void printDiscreteNonCorrectedChannelCapacity(Channel channel) {
		BlahutArimoto ba = new BlahutArimoto(channel, acceptableError, noOfIterations);

		//Find the capacity of a basic channel
		ba.calculateCapacity();
		double result = ba.getCapacity();
		inputDist = ba.getMaxInputDist();

		//Print the maximising input distribution
		if(verbose > 1) {
			System.out.println("Maximising input distribution estimated to be:");
			InfoTheory.printPMF(channel.getInputNames(), ba.getMaxInputDist());
			System.out.println();
		}
		
		//Print the result returned by Blahut-Arimoto Algorithm
		if(verbose > 1) {
			double possibleError = ba.getPossibleError();
			double acceptableError = ba.getAcceptableError();
			int iteration = ba.getIterationCount();
			if(possibleError == 0) { 
				System.out.println("  Blahut-Arimoto Algorithm terminated after " + iteration + " iterations.");
			} else if(possibleError <= acceptableError) { 
				System.out.println("  Capacity calculated to within acceptable error, in " +
								    iteration + " iterations.");
			} else if(possibleError > acceptableError) {
				System.out.println("  NOT COMPLETE: Performed the maximum number of iterations: " + iteration);
				System.out.println("  Possible error rate " + possibleError + " is still bigger than ");
				System.out.println("  the acceptable error rate " + acceptableError + ".");
				System.out.println("  Increase the maximum number of iterations (with option -i <int>)");
				System.out.println("  or increase the acceptable error (with option -e <double>).");
			}
		}
		
		leakage.add(result);
		System.out.printf("Capacity: %1$6.4g \n", result);
		if (verbose > 3) {
			System.out.println("  Acceptable error level for Blahut-Arimoto Algorithm: " + acceptableError);
		}
		// Print conclusion on leakage
		System.out.printf("The attacker learns %6.4g bits", result);
		System.out.printf(", out of a possible %6.4g bits, about the input events.",
						  InfoTheory.log2(channel.noOfInputs()));
		System.out.println();
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(ERROR);
		upperLimit.add(ERROR);
		confidence.add("USEFUL     ");
	}


    /*
     * Calculates and prints the confidence of the estimated corrected capacity.
     * 
	 * @param channel channel
	 * @param sampleSize sample size
     */
	private void printDiscreteCorrectedChannelCapacity(Channel channel, int sampleSize) {
		BlahutArimoto ba = new BlahutArimoto(channel, acceptableError, noOfIterations);

		//Find the capacity of a basic channel
		ba.calculateCapacity();
		double result = ba.getCapacity();
		inputDist = ba.getMaxInputDist();

		//Correction
		double correction = (double)(channel.noOfInputs()-1)*(double)(channel.noOfOutputs()-1)
						  / (double)(2*sampleSize)*InfoTheory.log2(Math.E);
		double mean = Math.max(0.0, result - correction);

		if(!checkEachFeature || verbose > 1) {
			System.out.print("Estimated capacity: ");
			System.out.print(Stats.round(mean,4));
			System.out.printf(" (out of possible %6.4g bits)\n",
						      InfoTheory.log2(channel.noOfInputs()));
		 	if(verbose > 3) {
		 		System.out.println("  Acceptable error level for Blahut-Arimoto Algorithm: " + acceptableError);
		 	}
			if(verbose > 2) {
				System.out.println("  noOfInputs: " + channel.noOfInputs() +
								   "  noOfOutputs " + channel.noOfOutputs());
			}
		}
		
		if( (channel.noOfInputs() <= 1) || channel.noOfOutputs() <= 1 ) {
			if(!checkEachFeature || verbose > 1) {
				System.out.println("It is impossible to calculate zero information leakage.");
			}
			if(verbose > 2) {
				System.out.println("  The numbers of inputs =  " + channel.noOfInputs());
				System.out.println("  The numbers of outputs = " + channel.noOfOutputs());
				System.out.println("  These values must not be 1.");
			}
			leakage.add(mean);
			zeroLimit.add(ERROR);
			lowerLimit.add(ERROR);
			upperLimit.add(ERROR);
			confidence.add("NOT SURE   ");
		} else {
			double zeroUpperBound = Stats.upperBoundForZero( (channel.noOfInputs()-1)*(channel.noOfOutputs()-1), sampleSize ); 
			double variance = Estimate.VarianceOfEstimatedMIUnderEstimatedPrior(inputDist, channel.getMatrix(), sampleSize);
			double lower = Stats.round(Math.max(0.0, Stats.lowerBoundNormal95(mean, variance)),4);
			double upper = Stats.round(Stats.upperBoundNormal95(mean, variance),4);
			
			//Print the output, depending on the value of verbose
			//the higher "verbose" the more details given.
			if(verbose > 2) {
				System.out.println("  Correction = log_2(e).(noOfInputs-1)(noOfOutputs-1)/2.sampleSize = " +
									Stats.round(correction,4));
				//System.out.println("   The results are no more accurate that the correction value,");
				//System.out.println("   increase the sample size to decrease the correction.");
				System.out.printf("  Mean:     " + Stats.round(mean,4) + " (= "
								  + Stats.round(result,4) + " - " + Stats.round(correction, 4) + ")\n");
				System.out.printf("  Variance: %1$6.4g \n", variance);
			}
			
			if(!checkEachFeature || verbose > 1) {
				System.out.println("  Between " + lower + " and " + upper + " with 95% confidence");
				System.out.println("  With 95% confidence, if leakage (w/o correction) < " + Stats.round(zeroUpperBound,4) + ", we may consider no information is leaked.");
				
				if(result <= zeroUpperBound) {
					System.out.println("No leak detected.");
				} else {
					System.out.println("There is a leak.");
				}
			}
			
			leakage.add(mean);
			zeroLimit.add(zeroUpperBound);
			lowerLimit.add(lower);
			upperLimit.add(upper);
			if(zeroUpperBound == ERROR)
				confidence.add("NOT SURE   ");
			else {
				if(result <= zeroUpperBound)
					confidence.add("ZERO LEAK  ");
				else
					confidence.add("LEAK       ");
			}
		}
	}


	/*
	 * Calculates and prints the min-entropy leakage.
	 * 
	 * @param pd input probability distribution
	 * @param channel channel
	 */
	private void printDiscreteMinEntropyLeakOnly(ProbDist pd, Channel channel) {
		double result;
		if(priorNonUniform) {
			result = MinEntropy.minEntropyLeak(pd, channel);
			if(result == ERROR) {
				System.out.println("Error: Failed to calculate min-entropy leakage.");
				//System.out.println("  MEL = " + result);
				return;
			}
			if(verbose == -1) {
				System.out.printf("%1$6.4g", result);
				return;
			}
			if(!checkEachFeature || verbose > 1) {
				System.out.printf("Min-entropy leakage: %1$6.4g  ", result);
				System.out.printf(" (out of possible %6.4g bits)\n", MinEntropy.minEntropy(pd));
				if(verbose > 4) {
					System.out.println("  -log(a priori vulnerability):     " + MinEntropy.minEntropy(pd));
					System.out.println("  -log(a posteriori vulnerability): " + MinEntropy.conditionalMinEntropy(pd, channel));
				}
				System.out.println();
			}
		} else {
			double[] dist = InfoTheory.uniformDist(channel.getMatrix().length);
			result = MinEntropy.minEntropyLeak(dist, channel.getMatrix());
			if(verbose == -1) {
				System.out.printf("%1$6.4g", result);
				return;
			}
			if(!checkEachFeature || verbose > 1) {
				System.out.printf("Min-entropy leakage: %1$6.4g  ", result);
				System.out.printf(" (out of possible %6.4g bits)\n", InfoTheory.log2(channel.noOfInputs()));
				System.out.println("  Calculated with the uniform input distribution.");
				if(verbose > 4) {
					System.out.println("  -log(a priori vulnerability):     " + MinEntropy.minEntropy(dist));
					System.out.println("  -log(a posteriori vulnerability): " + MinEntropy.conditionalMinEntropy(dist, channel.getMatrix()));
				}
				System.out.println();
			}
		}
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(ERROR);
		upperLimit.add(ERROR);
		confidence.add("NOT SURE   ");
	}


    /*
     * Prints the confidence interval of the estimated min-entropy leakage
     * using information-theoretic bounds presetend in [Vajda'02] & [Dutta, Goswami'10].
     * 
	 * @param channel channel
	 * @param sampleSize the size of samples
	 * @param sampleSizeGivenOutput array of the sample size given each output
	 */
	private void printDiscreteMinEntropyLeakWithInterval(ProbDist pd, Channel channel, int sampleSize, int[] sampleSizeGivenOutput) {
		double[] dist;
		if(priorNonUniform) {
			dist = pd.probDistToPMFArray(channel.getInputNames());
		} else {
			dist = InfoTheory.uniformDist(channel.getMatrix().length);
		}
		double result = MinEntropy.minEntropyLeak(dist, channel.getMatrix());
		if(result <= -1) {
			System.out.printf("Error: Failed to calculate min-entropy leakage.");
			return;
		}
		
		/**/
		// Old version based on the lemma ver 20130114
		double possibleErrorOld = MinEntropy.minEntropyLeakError20130114(dist, channel.getMatrix(),
															  		  sampleSize, channel.noOfOutputs());
		double lower = Math.max(0.0, result - possibleErrorOld);
		double upper = Math.min(InfoTheory.log2(channel.noOfInputs()), result + possibleErrorOld);
		System.out.println("  old confidence interval = [" + lower + ", " + upper + "]");
		 /**/
		
		double[] MELintervalNew = MinEntropy.minEntropyLeakConfidenceIntervalVajda(dist, channel.getMatrix(), sampleSize, sampleSizeGivenOutput, channel.noOfOutputs());
		double MELlower = MELintervalNew[0];
		double MELupper = MELintervalNew[1];
		double possibleError = Math.max(result - MELlower, MELupper-result);
		
		if(!checkEachFeature || verbose > 1) {
			System.out.print("Estimated min-entropy leakage: ");
	 		System.out.print(Stats.round(result,4));
			if(priorNonUniform) {
				System.out.printf(" (out of possible %6.4g bits)\n", MinEntropy.minEntropy(pd));
			} else {
				System.out.printf(" (out of possible %6.4g bits)\n", InfoTheory.log2(channel.noOfInputs()));
				System.out.println("  Calculated with the uniform input distribution.");
			}
			if(verbose > 4) {
				System.out.println("  -log(a priori vulnerability):     " + MinEntropy.minEntropy(dist));
				System.out.println("  -log(a posteriori vulnerability): " + MinEntropy.conditionalMinEntropy(dist, channel.getMatrix()));
			}
			System.out.println("  Possible error: " + Stats.round(possibleError,4));
			if(verbose >= 7) {
				System.out.println("Old wrong version 14/01/2013: ");
				System.out.println("* Between " + Stats.round(lower,4) +
				  				   " and " + Stats.round(upper,4) + " with 95% confidence");
			}
			System.out.println("  Between " + Stats.round(MELlower,4) +
			  				   " and " + Stats.round(MELupper,4) + " with 95% confidence");

			// Print conclusion on leakage
			if(MELlower > 0) {
				System.out.print("There is a leak.");
			} else if(Double.isNaN(MELlower)) {
				System.out.println("Too small sample size");
			} else {
				System.out.println("No leak detected.");
			}
			System.out.println();
		}
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(MELlower);
		upperLimit.add(MELupper);
		if(MELlower > 0)
			confidence.add("INFO LEAK  ");
		else
			confidence.add("NOT SURE   ");
	}


    /*
     * Prints the confidence interval of the estimated min-entropy leakage
     * using the binomial distribution method.
	 * @param channel channel
	 * @param sampleSize the size of samples
	 * @param obs observations
	 */
	private void printDiscreteMinEntropyLeakWithNewInterval(ProbDist pd, Channel channel, int sampleSize, Observations obs) {
		// Confidence level 0.95 is fixed
		final double minConfidenceLevel = 0.95;
		//System.out.println("Minimum confidence level: " + minConfidenceLevel);

		// Calculate min-entropy leakage
		final double condProb[][] = channel.getMatrix();
		double[] dist;
		if(priorNonUniform) {
			dist = pd.probDistToPMFArray(channel.getInputNames());
		} else {
			dist = InfoTheory.uniformDist(condProb.length);
		}
		double result = MinEntropy.minEntropyLeak(dist, condProb);
		if(result <= -1) {
			System.out.printf("Error: Failed to calculate min-entropy leakage.");
			return;
		}

		double[] interval = MinEntropy.minEntropyLeakConfidenceIntervalChiSquare(obs);
		double lowerBoundInterval = interval[0];
		double upperBoundInterval = interval[1];
		//double lowerBoundInterval = InfoTheory.minEntropyLeakLowerBoundBinomial(dist, condProb, sampleSizeGivenInput);
		//double upperBoundInterval = InfoTheory.minEntropyLeakUpperBoundBinomial(dist, condProb, sampleSizeGivenInput);
		
		double possibleError = Math.max(result-lowerBoundInterval, upperBoundInterval-result);

		if(!checkEachFeature || verbose > 1) {
			System.out.print("Estimated min-entropy leakage: ");
	 		System.out.print(Stats.round(result,4));
			if(priorNonUniform) {
				System.out.printf(" (out of possible %6.4g bits)\n", MinEntropy.minEntropy(pd));
			} else {
				System.out.printf(" (out of possible %6.4g bits)\n", InfoTheory.log2(channel.noOfInputs()));
				System.out.println("  Calculated with the uniform input distribution.");
			}
			if(verbose > 4) {
				System.out.println("  -log(a priori vulnerability):     " + MinEntropy.minEntropy(dist));
				System.out.println("  -log(a posteriori vulnerability): " + MinEntropy.conditionalMinEntropy(dist, channel.getMatrix()));
			}
			System.out.println("  Possible error: " + Stats.round(possibleError,4));
			System.out.println("  Between " + Stats.round(lowerBoundInterval,4) +
							   " and " + Stats.round(upperBoundInterval,4) +
							   " with " + (100*minConfidenceLevel) + "% confidence");

			// Print conclusion on leakage
			if(lowerBoundInterval > 0) {
				System.out.print("There is a leak.");
			} else if(Double.isNaN(lowerBoundInterval)) {
				System.out.println("Too small sample size.");
			} else {
				System.out.println("No leak detected.");
				//System.out.print("More observation data are needed.");
			}
			System.out.println();
		}
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(lowerBoundInterval);
		upperLimit.add(upperBoundInterval);
		if(lowerBoundInterval > 0)
			confidence.add("INFO LEAK  ");
		else
			confidence.add("NOT SURE   ");
		//testMEL(dist, channel, result, sampleSize);
	}


	
    /*
     * Calculate and prints the min-capacity.
     * 
     * @param channel channel
     */
	private void printDiscreteMinCapacity(Channel channel) {
		double result = MinEntropy.minCapacity(channel.getMatrix());
		if(verbose == -1) {
			System.out.printf("%1$6.4g", result);
			return;
		}
		if(!checkEachFeature || verbose > 1) {
			// Print conclusion on leakage
			System.out.printf("Min-capacity: %1$6.4g", result);
			System.out.printf(" (out of possible %6.4g bits)\n",
					  InfoTheory.log2(channel.noOfInputs()));
			System.out.printf("  Note that this result does not take account of confidence interval.");
			System.out.println();
		}
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(ERROR);
		upperLimit.add(ERROR);
		confidence.add("NOT SURE   ");
	}

	
	/*
	 * Calculates and prints the g-leakage.
	 * TODO: Check this method!
	 * 
	 * @param pd input probability distribution
	 * @param channel channel
	 * @param gf gain function
	 * @param guessDomain guess domain
	 * 
	 */
	private void printDiscreteGLeakageOnly(ProbDist pd, Channel channel, GainFunction gf, Set<String> guessDomain) {
		// set a uniform distribution if prior is not specified
		if(!(priorNonUniform)) {
			pd = ProbDist.uniformProbDist(channel.getInputNames(), true);
			if(verbose >= 5)
				System.out.println("The uniform distribution is assumed.");
		}

		// check whether each guess in guessDomain is contained in pd
		if(!GainFunction.checkConsistency(pd, guessDomain)) {
			System.out.println("Error: There is a guess not found in the prior.");
			System.exit(1);
		}
		
		// calculate g-leakage
		double result = GLeakage.gLeakage(pd, channel, gf, guessDomain);
		if(result <= -1) {
			System.out.printf("Error: Failed to calculate g-leakage.");
			return;
		}

		if(verbose == -1) {
			System.out.printf("%1$6.4g", result);
			return;
		}
		if(!checkEachFeature || verbose > 1) {
			System.out.printf("g-leakage: %1$6.4g  ", result);
			System.out.printf(" (out of possible %6.4g bits)\n",
							   GLeakage.gEntropy(pd, gf, guessDomain));
			if(!(priorNonUniform)) {
				System.out.println("  Calculated with the uniform input distribution.");
			}
			if(verbose > 4) {
				System.out.println("  -log(a priori g-vulnerability):     " + GLeakage.gEntropy(pd, gf, guessDomain));
				System.out.println("  -log(a posteriori g-vulnerability): " + GLeakage.conditionalGEntropy(pd, channel, gf, guessDomain));
			}
			System.out.println();
		}
		
		leakage.add(result);
		zeroLimit.add(ERROR);
		lowerLimit.add(ERROR);
		upperLimit.add(ERROR);
		confidence.add("NOT SURE   ");
	}


	/*
	 * Calculates and prints the mutual information for continuous observation.
	 * @param cdata continuous data
	 * @return estimated mutual information
	 */
	private int printContinuousMutualInformation(ContinuousData cdata) {
		ArrayList<double[]> DataList = cdata.DataList;
		int noOfTestsContinuous = cdata.testSize;
		//System.out.println("noOfTestsContinuous = " + noOfTestsContinuous);
		
		// For normal tests
		//
		//ContinuousData data = new ContinuousData();
		//data.generateNormalTimes(Same Mean, Same Sdt, Diff Mean, Diff Std, Sample size);
		//data.generateNormalTimes(0, 1, 0, 1.125, 1000);

		//
		// Find real MI
		//

		// Set up the pdfs
		KernelFunction kernel = new KernelFunction(DataList);

		// Calculate the empirical (discrete) input distribution
		double[] inputDist = kernel.probInputDist(DataList);
		
		// Calculate the approximation of mutual information using the continuous approximation
		double realMI = kernel.calcContinuousApproxMI(inputDist, cdata.DataList);
		if(realMI == ERROR) {
			System.out.print("We cannot estimate the mutual information. ");
			System.out.println("The ammount of observations is not enough.");
			return -1;
		}
		
		if(!checkEachFeature || verbose > 1) {
			System.out.print("Estimated mutual information: " + Stats.round(realMI,4));
			System.out.printf(" (out of possible %6.4g bits)\n",
					  		  ShannonEntropy.entropy(inputDist));
		}

		// When skipping the zero leakage test
		if(skipZLT) {
			leakage.add(realMI);
			zeroLimit.add(ERROR);
			lowerLimit.add(ERROR);
			upperLimit.add(ERROR);
			confidence.add("NOT SURE   ");
			return 0;
		}
		
		// Zero leakage tests
		// Run tests for 0 MI
		//
		double[] miResultsZ = new double[noOfTestsContinuous];
		double miTotalZ = 0;
		for(int i = 0; i < noOfTestsContinuous; i++) {
			// Set up the pdfs
			ArrayList<double[]> shuffledDataList = cdata.selectShuffled(inputDist);
			if(shuffledDataList == null) {
				return -1;
			}

			kernel = new KernelFunction(shuffledDataList);

			//Calculate the approximation of mutual information using the continuous approximation
			double continuousApproxMI = kernel.calcContinuousApproxMI(inputDist, shuffledDataList);
			miResultsZ[i] = continuousApproxMI;
			miTotalZ += continuousApproxMI;
		}
		// calculate the 95 percentile for shuffled values
		Arrays.sort(miResultsZ);
		double percentileValue = miResultsZ[(int) ((miResultsZ.length)*0.95)];
		
		if(!checkEachFeature || verbose > 1) {
			if(realMI < percentileValue) {
				System.out.println("No leak detected.");
				System.out.println("  Estimate is below " + Stats.round(percentileValue,4) + "(the 95 percentile for shuffled values).");
			} else {
				System.out.println("There is a leak.");
				System.out.println("  Estimate is NOT below " + Stats.round(percentileValue,4) + "(the 95 percentile for shuffled values).");
			}
		}

		if(!checkEachFeature || verbose > 1) {
			if(verbose > 2) {
				double averageZero = miTotalZ / (double)noOfTestsContinuous;
				double stdDevZero = Stats.sdtDevSampled(miResultsZ,miTotalZ);
				double upperbound = Stats.upperBoundNormal95Upper(averageZero, stdDevZero*stdDevZero);
				System.out.print("In zero leakage tests, ");
				System.out.println("the mutual information for " + noOfTestsContinuous + " SHUFFLED samples has");
				System.out.println("  Average:                         " + Stats.round(averageZero,4));
				System.out.println("  Standard devation:               " + Stats.round(stdDevZero,4));
				System.out.println("  Upper 95% limit for normal dist: " + Stats.round(upperbound,4));
			}
		}
		/*
		if(!checkEachFeature || verbose > 1) {
			if(verbose > 3) {
				if(realMI < upperbound) {
					System.out.println("No leak detected.");
					System.out.println("  Upper 95% limit for normal dist of Zero results: " + Stats.round(upperbound,4));
					System.out.println("  Estimate is in the 95% interval for shuffled values.");
				} else {
					System.out.println("There is a leak.");
					System.out.println("  Upper 95% limit for normal dist of Zero results: " + Stats.round(upperbound,4));
					System.out.println("  Estimate is NOT in the 95% interval for shuffled values.");
				}
			}
		}
		*/
		

		leakage.add(realMI);
		//zeroLimit.add(upperbound);
		zeroLimit.add(percentileValue);
		lowerLimit.add(ERROR);
		upperLimit.add(ERROR);
		//if(realMI < upperbound)
		if(realMI < percentileValue)
			confidence.add("ZERO LEAK  ");
		else
			confidence.add("LEAK       ");
		return 0;
	}



	////////////////////////////
	////// Print functions /////
	/*
	 * Print the list of all results.
	 * 
	 * @param taskType type of calculation of a leakage measure
	 * @param name array of strings representing features
	 */
	protected void printAllResults(int taskType, ArrayList<String> name) {
		ArrayList<Pair<String,Integer>> sortIndex = new ArrayList<Pair<String,Integer>>();
		//ArrayList<StringWithSortIndex> sortIndex = new ArrayList<StringWithSortIndex>();
		int maxlen = 0;
		for(int i = 0; i < leakage.size(); i++) {
			Pair<String,Integer> swsi = new Pair<String,Integer>(leakage.get(i).toString(), i);
			//StringWithSortIndex swsi = new StringWithSortIndex();
			//swsi.setValues(leakage.get(i).toString(), i);
			sortIndex.add(swsi);
			if(name != null && name.size() > i) {
				maxlen = Math.max(maxlen, name.get(i).length());
			}
		}

        //ComparatorMulti comparator = new ComparatorMulti();
        ComparatorStringWithInt comparator = new ComparatorStringWithInt();
		Collections.sort(sortIndex, comparator);

		System.out.println("");
		System.out.println("--------------------------------------------------------------------------------");
		System.out.print("  Information leakage from the ");
		if(OBS_DISCRETE)
			System.out.print("discrete outputs ");
		else
			System.out.print("continuous outputs ");
		System.out.println("about the inputs, measured by");
		switch(taskType) {
		case(CLC_MUTUAL_INFO):
			System.out.println("  mutual information (calculated with the uniform input distribution):");
			break;
		case(CLC_CAPACITY):
			System.out.println("  capacity:");
			break;
		case(CLC_MIN_ENTROPY):
			System.out.println("  min-entropy leakage (calculated with the uniform input distribution):");
			break;
		case(CLC_MIN_CAPACITY):
			System.out.println("  min-capacity:");
			break;
		}
		System.out.println("--------------------------------------------------------------------------------");
		System.out.print("Confidence Result     Attributions");
		for(int j = 0; j < maxlen; j++)
			System.out.print(" ");
		System.out.println("          Range (with 95% confidence)");


		for(int i = leakage.size() - 1; i >= 0; i--) {
			//int j = sortIndex.get(i).getSortIndex();
			int j = sortIndex.get(i).getElement2();

			// print "no useful" or not
			System.out.print(confidence.get(j));
			
			// print leakage
			if(leakage.get(j) != ERROR)
				System.out.format("%.3f for%s", leakage.get(j), name.get(j));
			else
				System.out.format("ERROR for%s", name.get(j));
			
			// adjust space
			for(int k = 0; k < maxlen - name.get(j).length(); k++)
				System.out.print(" ");
			
			// print zero leakage
			if(zeroLimit.get(j) != ERROR)
				System.out.format("  zero leakage < %.3f", zeroLimit.get(j));
			else
				System.out.format("                      ");
			
			// print 95% confidence interval
			if(lowerLimit.get(j) != ERROR || upperLimit.get(j) != ERROR) {
				// print lower limit
				if(lowerLimit.get(j) != ERROR)
					System.out.format("  [%.3f, ", Math.max(0.0,lowerLimit.get(j)));
				else
					System.out.format("  [  ?  , ");

				// print upper limit
				if(upperLimit.get(j) != ERROR)
					System.out.format("%.3f]", upperLimit.get(j));
				else
					System.out.format("   ? ]");
			}
			System.out.println("");
		}
	}


	
}
