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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.Iterator;
import java.io.*;

import bham.leakiest.comparator.*;
import bham.leakiest.infotheory.*;

/**
 * This is the main class of the tool leakiEst:
 * a suite of tools to Calculate the information leakage of a system.
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.4.9
 */
public class TestInfoLeak {
	// Version
	static String version = "1.4.8.2";
	
	// File type
	//static final int ChanFile = 1; 

	// Constants on task types
	static final int CLC_MUTUAL_INFO = 1;
	static final int CLC_CAPACITY = 2;
	static final int CLC_MIN_ENTROPY = 3;
	static final int CLC_MIN_CAPACITY = 4;
	static final int CLC_G_LEAK = 5;
	
	// Constants on file types
	static final int READ_CFG = -2;
	static final int READ_ERROR = -1;
	static final int READ_ARFF = 0;
	static final int READ_CH = 1;
	static final int READ_OBS1 = 2;
	static final int READ_OBS2 = 3;
	static final int READ_PRIOR = 4;
	static final int READ_GUESS = 5;
	
	// Constants relating to automatic termination
	// after corrected leakage stabilises
	static final int LEAKAGE_STABILISATION_INITIAL_INTERVAL = 100; // the initial number of samples to read before creating the first and second intervals
	static final double LEAKAGE_STABILISATION_DELTA = 0.01; // if leakages at successive intervals differ by less than this amount, terminate
	
	// Other constants
	static final double ERROR = -1;
	static final double UNKNOWN = -2;
	static final double APPROX_OPTIMIZED = 10.0;

	// Features for high values
	static TreeSet<Integer> highFeatures = new TreeSet<Integer>();
	static TreeSet<String> highFeaturesSet = new TreeSet<String>();

	// Features for low values
	static TreeSet<Integer> lowFeatures = new TreeSet<Integer>();
	static TreeSet<String> lowFeaturesSet = new TreeSet<String>();

	// Checking each feature for low values (or not)
	static boolean checkEachFeature = false;

	// Default options (that can be override by the commandline).
	static boolean readFromChanFile = false; 
	static boolean readFromCfgFile = false;
	static boolean readFromObsFile = false;
	static boolean readFrom2ObsFiles = false;
	static boolean readFromARFFFile = false;
	static boolean readFromPriorFile = false;
	static boolean readFromGuessFile = false;
	static boolean ignoreOptionDis = false;
	static boolean ignoreOptionCfg = false;
	static boolean ignoreOptionDir = false;
	static boolean ignoreOptionIn = false;
	static boolean ignoreOptionOut = false;
	static boolean ignoreOptionPrior = false;
	static boolean ignoreOptionGuess = false;
	static boolean ignoreOptionNOCR = false;
	static boolean ignoreOptionAPPROX = false;
	static boolean ignoreOptionAJS  = false;
	static boolean ignoreOptionPM = false;
	static boolean ignoreOptionPJ = false;
	static boolean ignoreOptionCSV = false;
	static boolean ignoreOptionTerminate = false;
	static int taskType = CLC_MUTUAL_INFO;
	static boolean compositionalEstimate = false;
	static boolean priorShared = false;
	static boolean skipZLT = false;
	static boolean correctLeak = true;
	static boolean correctLeakNew = true;
	static double approxPriorLevel = 0;
	static boolean approxDoNotKnowChannels = false;
	static boolean checkJointlySupported = true;
	static int fileType = READ_CH;
	static boolean OBS_DISCRETE = true;
	static boolean debugCode = false;
	
	static boolean PRINT_CHANNELMATRIX = false;
	static boolean PRINT_JOINTMATRIX = false;
	public static int verbose = 0;
	static double acceptableError = 0.000000000001;
	static int noOfIterations = 10000;
	static int noOfTestsContinuous = 200;
    protected static boolean fixMeanForPassportAnalyses = false; // Only used for PassportAnalyses 
    protected static boolean fixMedianForPassportAnalyses = false; // Only used for PassportAnalyses 

	static Observations obs;
	private static int numChannels = 1;
	static Channel channel;
	static Channel[] channels;
	static ContinuousData cdata;
	private static int numPriors = 1;
	static ProbDist[] pds;
	static Set<String> guessDomain;
	static String nameGainFunction;
	static GainFunction gf;
	
	static String cfgFileName = "";       // cfgFileName is set by the commandline
	static String directoryName = "";     // directoryName is set by the commandline
	static String dataFileName = "";      // dataFileName is set by the commandline
	static String dataFileName2 = "";     // dataFileName2 is set by the commandline
	static String[] dataFileNames;        // dataFileNames[] is set by the commandline
	static String[] priorFileNames;       // priorFileNames[] is set by the commandline
	static String guessFileName = "";     // guessFileName is set by the commandline
	static int csvEstimationInterval = 0; // set by the command-line option "-csv"
	static CSVFile csvFile;               // set by the command-line option "-csv"
	static boolean terminateWhenStabilised = false; // set by the command-line option "-t"
	static boolean priorNonUniform = false;  // set by the file types from the command-line

	static int sampleSize = 0;
	static int[] sampleSizeGivenInput;
	static int[] sampleSizeGivenOutput;

	static ArrayList<String> name = new ArrayList<String>();

	/**
	 * The main method of LeakiEst, a tool for estimating information leakage of systems.
	 * 
	 * @param args inputs from user
	 */
	public static void main(String[] args) {
		CommandLine cl = new CommandLine(args);
		// Features for high values
		highFeatures = cl.highFeatures;
		highFeaturesSet = cl.highFeaturesSet;

		// Features for low values
		lowFeatures = cl.lowFeatures;
		lowFeaturesSet = cl.lowFeaturesSet;

		// Checking each feature for low values (or not)
		checkEachFeature = cl.checkEachFeature;

		// Options override by the commandline
		readFromChanFile = cl.readFromChanFile; 
		readFromCfgFile = cl.readFromCfgFile;
		readFromObsFile = cl.readFromObsFile;
		readFrom2ObsFiles = cl.readFrom2ObsFiles;
		readFromARFFFile = cl.readFromARFFFile;
		readFromPriorFile = cl.readFromPriorFile;
		readFromGuessFile = cl.readFromGuessFile;
		ignoreOptionDis = cl.ignoreOptionDis;
		ignoreOptionCfg = cl.ignoreOptionCfg;
		ignoreOptionDir = cl.ignoreOptionDir;
		ignoreOptionIn = cl.ignoreOptionIn;
		ignoreOptionOut = cl.ignoreOptionOut;
		ignoreOptionPrior = cl.ignoreOptionPrior;
		ignoreOptionGuess = cl.ignoreOptionGuess;
		ignoreOptionNOCR = cl.ignoreOptionNOCR;
		ignoreOptionAPPROX = cl.ignoreOptionAPPROX;
		ignoreOptionAJS  = cl.ignoreOptionAJS;
		ignoreOptionPM = cl.ignoreOptionPM;
		ignoreOptionPJ = cl.ignoreOptionPJ;
		ignoreOptionCSV = cl.ignoreOptionCSV;
		ignoreOptionTerminate = cl.ignoreOptionTerminate;
		taskType = cl.taskType;
		compositionalEstimate = cl.compositionalEstimate;
		priorShared = cl.priorShared;
		skipZLT = cl.skipZLT;
		correctLeak = cl.correctLeak;
		correctLeakNew = cl.correctLeakNew;
		approxPriorLevel = cl.approxPriorLevel;
		approxDoNotKnowChannels = cl.approxDoNotKnowChannels;
		checkJointlySupported = cl.checkJointlySupported;
		fileType = cl.fileType;
		OBS_DISCRETE = cl.OBS_DISCRETE;
		debugCode = cl.debugCode;
		
		PRINT_CHANNELMATRIX = cl.PRINT_CHANNELMATRIX;
		PRINT_JOINTMATRIX = cl.PRINT_JOINTMATRIX;
		verbose = cl.verbose;
		acceptableError = cl.acceptableError;
		noOfIterations = cl.noOfIterations;
		noOfTestsContinuous = cl.noOfTestsContinuous;
	    fixMeanForPassportAnalyses = cl.fixMeanForPassportAnalyses;
	    fixMedianForPassportAnalyses = cl.fixMedianForPassportAnalyses;

		numChannels = cl.numChannels;
		channels = cl.channels;
		numPriors = cl.numPriors;
		pds = cl.pds;
		nameGainFunction = cl.nameGainFunction;
		gf = cl.gf;
		
		cfgFileName = cl.cfgFileName;
		directoryName = cl.directoryName;
		dataFileName = cl.dataFileName;
		dataFileName2 = cl.dataFileName2;
		dataFileNames = cl.dataFileNames;
		priorFileNames = cl.priorFileNames;
		guessFileName = cl.guessFileName;
		csvEstimationInterval = cl.csvEstimationInterval;
		csvFile = cl.csvFile;
		terminateWhenStabilised = cl.terminateWhenStabilised;

		// Constructor for pring the information leakage info
		PrintLeakageValue plv = new PrintLeakageValue(PRINT_CHANNELMATRIX, PRINT_JOINTMATRIX, verbose, acceptableError, noOfIterations, OBS_DISCRETE, readFromChanFile, skipZLT, correctLeak, correctLeakNew);

		// parameter for calcuating the information leakage
		//priorNonUniform = (readFromPriorFile || readFromObsFile || readFrom2ObsFiles) & OBS_DISCRETE;
		priorNonUniform = (readFromPriorFile || !readFromChanFile);
		//System.out.println("priorNonUniform = " + priorNonUniform);
		//System.out.println("readFromPriorFile = " + readFromPriorFile);
		//System.out.println("readFromObsFile   = " + readFromObsFile);
		//System.out.println("readFromChanFile  = " + readFromChanFile);
	
		//
		// Read in the channel file
		//
		// reading a discrete observations file and calculate a channel
		if(readFromObsFile && OBS_DISCRETE) {
			ReadFile obsReader = (csvFile == null ? new ReadFile(dataFileName, verbose, "discrete observations") : new ReadFile(dataFileName, verbose, csvEstimationInterval, csvFile));
			obsReader.setTerminateWhenStabilised(terminateWhenStabilised);
			obsReader.readObservations();
			obs = obsReader.getObservations();
			if(verbose > 1)
				System.out.println("Calculating the channel matrix...");
			channel = obs.generateChannel();
			pds = new ProbDist[1];
			pds[0] = obs.getInputProbDist();
			if(verbose >= 5) {
				System.out.println("Input distribution:");
				pds[0].printProbDist();
			}
			sampleSize = obs.getSampleCount();
			sampleSizeGivenInput = obs.getSampleCountGivenInput();
			sampleSizeGivenOutput = obs.getSampleCountGivenOutput();
			
			// Print the observations matrix
			if (verbose > 3) {
				obs.printObservationsMatrix();
			}

			//channel.printSaveChannel("/home/user/matrix.txt");
			if(verbose > 4) {
				System.out.println("\nThe largest "+ obs.certainty*100+"% confidence interval for any entry, to 4 decimal places, is "+Stats.round((2*obs.largestInterval()),4));
				//System.out.println("\n With certainty: "+ obs.totalCertainty()+" the largest confidence interval is: "+(2*obs.largestInterval()));
				//System.out.println("\n Max error ratio is: "+ obs.maxErrorRatio()+" the min error ratio is :"+ obs.minErrorRatio());
			}
		}

		// reading a continuous observations file and calculate a channel
		if(readFromObsFile && !OBS_DISCRETE) {
			ReadFile obsReader = new ReadFile(dataFileName, verbose, "continuous observations");
			obsReader.readContinuousObservations();
			cdata = obsReader.getContinuousData();
		}
		
		// reading two discrete observations files and calculate a channel
		if(readFrom2ObsFiles && OBS_DISCRETE) {
			ReadFile obsReader = (csvFile == null ? new ReadFile(dataFileName, dataFileName2, verbose, "discrete observations") : new ReadFile(dataFileName, dataFileName2, verbose, csvEstimationInterval, csvFile));
			obsReader.setTerminateWhenStabilised(terminateWhenStabilised);
			obsReader.read2DiscreteObservationsFiles();
			obs = obsReader.getObservations();
			if(verbose > 1)
				System.out.println("Calculating the channel matrix...");
			channel = obs.generateChannel();
			pds = new ProbDist[1];
			pds[0] = obs.getInputProbDist();
			sampleSize = obs.getSampleCount();
			sampleSizeGivenInput = obs.getSampleCountGivenInput();
			sampleSizeGivenOutput = obs.getSampleCountGivenOutput();

			//channel.printSaveChannel("/home/user/matrix.txt");
			if(verbose > 4) {
				System.out.println("\nThe largest "+ obs.certainty*100+"% confidence interval for any entry, to 4 decimal places, is "+Stats.round((2*obs.largestInterval()),4));
				//System.out.println("\n With certainty: "+ obs.totalCertainty()+" the largest confidence interval is: "+(2*obs.largestInterval()));
				//System.out.println("\n Max error ratio is: "+ obs.maxErrorRatio()+" the min error ratio is :"+ obs.minErrorRatio());
			}
		}
		
		// reading two continuous observations files and prepare a data array
		if(readFrom2ObsFiles && !OBS_DISCRETE) {
			ReadFile obsReader = new ReadFile(dataFileName, dataFileName2, verbose, "continuous observations");
			obsReader.read2ContinuousObservationsFiles();
			cdata = obsReader.getContinuousData();
		}
		
		// reading the (discrete) channel from a channel file
		if(readFromChanFile) {
			for(int ic = 0; ic < numChannels; ic++) {
				//System.out.println("  " + ic + " " + dataFileNames[ic]);
				if(dataFileNames != null && ic < dataFileNames.length && dataFileNames[ic]!= null) {
					// Read the channel matrix using the ReadFile Class
					ReadFile channelFileReader = new ReadFile(dataFileNames[ic], verbose, "discrete channel");
					channelFileReader.readChannel();
					channels[ic] = channelFileReader.getChannel();
				} else {
					System.out.println("Commandline error: Options for channel file names are not specified correctly.");
					System.out.println("  Number of channels specified: " + numChannels);
					System.exit(1);
				}
			}
		}

		// reading a discrete ARFF file and calculate a channel
		if(readFromARFFFile && OBS_DISCRETE) {  	
			// Read the ARFF file and generate a channel matrix using the ReadFile Class
			ARFFFile file = csvFile == null ? new ARFFFile(dataFileName, verbose) : new ARFFFile(dataFileName, verbose, csvEstimationInterval, csvFile);
			file.setTerminateWhenStabilised(terminateWhenStabilised);

			// Add high features specified by names
			highFeatures = file.getFeatureIndices(highFeatures, highFeaturesSet);
			
			// Add low features specified by names
			lowFeatures = file.getFeatureIndices(lowFeatures, lowFeaturesSet);

			// Add the last feature to highFeatures in case highFeatures is empty.
			if(highFeatures.size() < 1) {
				highFeatures.add(file.attributes.length - 1);
	    		System.out.println("Commandline option warning: -high <numbers> is missing or badly specified");
	    		System.out.println("Set -high " + (file.attributes.length - 1) + ".");
			}

			// Set @each in case lowFeatures is empty.
			if(lowFeatures.size() < 1 && checkEachFeature == false) {
				checkEachFeature = true;
	    		System.out.println("Commandline option warning: -low <numbers> is missing or badly specified");
	    		System.out.println("Set -low @each.");
	    		
	    		// Since we just implied @each as the value for -low, check again
				// that -csv wasn't given (it doesn't support -low @each)
				if (csvFile != null) {
					System.out.println("Incremental estimations of leakage can only be calculated when reading the following file types:");
					System.out.println("* Observations file containing discrete data");
					System.out.println("* 2 observations files containing discrete data");
					System.out.println("* ARFF file containing discrete data, with value of -low other than @each");
					CommandLine.printUsage();
					System.exit(1);
				}
			}
			
			// Calculate a channel
			if(checkEachFeature) { //Calculate a channel for each feature
				if(verbose <= 1)
					System.out.print("Processing attribute... ");
				else {
					System.out.println("");
					System.out.println("-----------------------------------------------------------------------------");
				}

				if(lowFeatures.size() >= 1) {
					// Print selected features
					file.printFeatures(highFeatures, lowFeatures, verbose);

					// Calculate the channel
					Observations obs0 = file.obsFromARFF(highFeatures, lowFeatures);
					if(verbose > 1)
						System.out.println("Calculating the channel matrix...");
					channel = obs0.generateChannel();
					sampleSize = obs0.getSampleCount();
					sampleSizeGivenInput = obs0.getSampleCountGivenInput();
					sampleSizeGivenOutput = obs0.getSampleCountGivenOutput();

					// Calculate the input dsitribution 
					pds = new ProbDist[1];
					pds[0] = obs0.getInputProbDist();

					// Calculate the information leakage
					plv.printMeasure(taskType, pds[0], channel, obs0, priorNonUniform, checkEachFeature);
				}
				
				for(int i = 0; i < file.attributes.length; i++) {
					if(!highFeatures.contains(i) && !lowFeatures.contains(i)) {
						if(verbose <= 1) {
							if(i % 10 == 0)
								System.out.println("");
							System.out.print(i + "/" + (file.attributes.length - 1) + "... ");
						}
						
						// Add one feature to the set of low features 
						TreeSet<Integer> lowFeaturesNow = (TreeSet<Integer>)lowFeatures.clone();
						lowFeaturesNow.add(i);
						
						// Print selected features
						if(verbose > 1) {
							System.out.println("-----------------------------------------------------------------------------");
						}
						file.printFeatures(highFeatures, lowFeaturesNow, verbose);

						// Calculate the channel
						Observations obs = file.obsFromARFF(highFeatures, lowFeaturesNow);
						if(verbose > 1)
							System.out.println("Calculating the channel matrix...");
						channel = obs.generateChannel();
						sampleSize = obs.getSampleCount();
						sampleSizeGivenInput = obs.getSampleCountGivenInput();
						sampleSizeGivenOutput = obs.getSampleCountGivenOutput();

						// Calculate the input dsitribution 
						pds = new ProbDist[1];
						pds[0] = obs.getInputProbDist();

						// Calculate the information leakage
						plv.printMeasure(taskType, pds[0], channel, obs, priorNonUniform, checkEachFeature);
						
						name.add(file.getStringLowFeatures(lowFeaturesNow, verbose));
					}
				}
				
				plv.printAllResults(taskType, name);
				System.exit(0);
			} else { //Calculate a channel only once
				// Print selected features
				file.printFeatures(highFeatures, lowFeatures, verbose);

				//Calculate a channel
				obs = file.obsFromARFF(highFeatures, lowFeatures);
				if(verbose > 1)
					System.out.println("Calculating the channel matrix...");
				channel = obs.generateChannel();
				sampleSize = obs.getSampleCount();
				sampleSizeGivenInput = obs.getSampleCountGivenInput();
				sampleSizeGivenOutput = obs.getSampleCountGivenOutput();
				
				// Calculate the input dsitribution
				pds = new ProbDist[1];
				pds[0] = obs.getInputProbDist();
			}
		}

		// reading a continuous ARFF file and prepare a data array
		if(readFromARFFFile && !OBS_DISCRETE) {  	
			// Read the ARFF file and generate a channel matrix using the ReadFile Class
			ARFFFile file = new ARFFFile(dataFileName, verbose);
			
			// Add high features specified by names
			highFeatures = file.getFeatureIndices(highFeatures, highFeaturesSet);
			
			// Add low features specified by names
			lowFeatures = file.getFeatureIndices(lowFeatures, lowFeaturesSet);

			// Add the last feature to highFeatures in case highFeatures is empty.
			if(highFeatures.size() < 1) {
				highFeatures.add(file.attributes.length - 1);
	    		System.out.println("Commandline option warning: -high <numbers> is missing or badly specified");
	    		System.out.println("Set -high " + (file.attributes.length - 1) + ".");
			}

			// Prepare a List of data arrays
			if(checkEachFeature) { //Calculate a channel for each feature
				if(verbose <= 1)
					System.out.print("Processing attribute... ");
				else {
					System.out.println("");
					System.out.println("-----------------------------------------------------------------------------");
				}

				if(lowFeatures.size() >= 1) {
					// Print selected features
					file.printFeatures(highFeatures, lowFeatures, verbose);
					// Prepare a data array
					cdata = file.cdataFromARFF(highFeatures, lowFeatures, verbose);
					sampleSize = file.noOfTests;
					// Calculate the information leakage
					if(cdata != null)
						plv.printMeasure(taskType, cdata, priorNonUniform, checkEachFeature);
				}

				// UPDATE THE FOLLOWING
				for(int i = 0; i < file.attributes.length; i++) {
					if(!highFeatures.contains(i) && !lowFeatures.contains(i)) {
						if(verbose <= 1) {
							if(i % 10 == 0)
								System.out.println("");
							System.out.print(i + "/" + (file.attributes.length - 1) + "... ");
						}
						// Add one feature to the set of low features 
						TreeSet<Integer> lowFeaturesNow = (TreeSet<Integer>)lowFeatures.clone();
						lowFeaturesNow.add(i);

						// Print selected features
						if(verbose > 1) {
							System.out.println("");
							System.out.println("-----------------------------------------------------------------------------");
							System.out.println("-----------------------------------------------------------------------------");
						}
						file.printFeatures(highFeatures, lowFeaturesNow, verbose);

						// Prepare a data array
						cdata = file.cdataFromARFF(highFeatures, lowFeaturesNow, verbose);
						sampleSize = file.noOfTests;
						
						 // Calculate the information leakage
						if(cdata != null)
							plv.printMeasure(taskType, cdata, priorNonUniform, checkEachFeature);
						name.add(file.getStringLowFeatures(lowFeaturesNow, verbose));
					}
				}
				plv.printAllResults(taskType, name);
				System.exit(0);
			} else { //Prepare a data array only once
				// Print selected features
				file.printFeatures(highFeatures, lowFeatures, verbose);
				cdata = file.cdataFromARFF(highFeatures, lowFeatures, verbose);
				sampleSize = file.noOfTests;
				if(cdata == null) {
					System.exit(1);
				}
			}
		}

		// reading a discrete prior (input) distribution file
		if(readFromPriorFile && OBS_DISCRETE) {
			for(int num = 0; num < numPriors; num++) {
				// Read the prior (input) distribution array using the ReadFile Class
				ReadFile priorFileReader = new ReadFile(priorFileNames[num], verbose, "marginal of discrete prior");
				priorFileReader.readDistribution();
				pds[num] = priorFileReader.getDistribution();
				if(verbose >= 5) {
					if(numPriors > 1) {
						System.out.println("Marginals of the input distribution:");
					} else {
						System.out.println("Joint (prior) input distribution:");
					}
					pds[num].printProbDist();
				}
			}
		}

		// reading a discrete guess file
		if(readFromGuessFile && OBS_DISCRETE) {  	
			// Read the guess domain array using the ReadFile Class
			ReadFile guessFileReader = new ReadFile(guessFileName, verbose, "discrete guess");
			guessFileReader.readGuessDomain();
			guessDomain = guessFileReader.getGuessDomain();
		}

		// debug
		if(debugCode) {
			if(verbose >= 5) {
				System.out.println("-------------------");
				System.out.println("Debug mode started.");
			}
			methodForDebug();
		}
		
		// parameter for calcuating the information leakage
		//priorNonUniform = (readFromPriorFile || readFromObsFile || readFrom2ObsFiles) && OBS_DISCRETE;

		// Calculate the information leakage
		if(OBS_DISCRETE) {  // case of discrete observation
			if(pds == null) {
				pds = new ProbDist[1];
			}
			if(!compositionalEstimate) { // exact calculation of the leakage measure
				if(priorShared && numChannels > 1) {
					// Check whether the sizes of the prior and channels are indentical 
					for(Channel ch : channels) {
						if(pds[0].sizeSampleSpace() != ch.noOfInputs()) {
							System.out.println("Error: The size of the (prior) input domain is larger than the channel matrix.");
							System.out.println("  the shared input domain size: " + pds[0].sizeSampleSpace());
							System.out.println("  the number of rows in the channel matrix: " + ch.noOfInputs());
							System.out.println("Failed to produce a shared input probability distribution.");
							System.exit(1);
						}
					}
					// Calculate a shared input distribution to calculate the exact leakage 
					if(taskType != CLC_MIN_ENTROPY) {
						pds[0] = pds[0].sharedProbDist(numChannels, true);
					}
				}
				if(numChannels > 1) {
					if(taskType == CLC_MIN_ENTROPY) {
						CompositionalEstimate.printExactDiscreteMinEntropyLeakOnly(pds, channels, priorShared);
					} else {
						/* Calculate the product of channels
						   when there is more than one channels */
						if(verbose >= 5) {
							System.out.println("Calculating the composed channel...");
						}
						Channel channel = Channel.parallelComposition(channels);
						// Exact calculation of the leakge measure
						plv.printMeasure(taskType, pds[0], channel, obs, priorNonUniform, checkEachFeature);
					}
				} else if(readFromChanFile) {
					plv.printMeasure(taskType, pds[0], channels[0], obs, priorNonUniform, checkEachFeature);
				} else {
					plv.printMeasure(taskType, pds[0], channel, obs, priorNonUniform, checkEachFeature);
				}
			} else if(readFromChanFile || readFromObsFile) { // compositional reasoning
				if(verbose >= 5) {
					System.out.println("Calculating bounds for the leakage measure...");
				}
				if(numChannels > 1) {
					// Compositional estimation of th leakage measure
					CompositionalEstimate.printEstimatedMeasure(taskType, pds, channels, numChannels, sampleSize, priorShared, gf, guessDomain, compositionalEstimate, approxPriorLevel, approxDoNotKnowChannels);
				} else {
					plv.printMeasure(taskType, pds[0], channels[0], obs, priorNonUniform, checkEachFeature);
				}
			} else {
				System.out.println("Error: The specified set of options is not supported.");
				System.exit(1);
			}
		}else {	// case of continuous observation
			plv.printMeasure(taskType, cdata, priorNonUniform, checkEachFeature);
		}
		
		// If the CSV file has been written to, close it (this also flushes any
		// text in the buffer that hasn't been written yet)
		if (csvFile != null) csvFile.close();
	}


	/*
	 * Debug the program.
	 */
	private static void methodForDebug() {
		
		//pd.getNumJoint();
	}
	
	/*
	 * Stops the execution of this program at a point.
	 * @param msg Message for debug.
	 */
	private static void debugStop(String msg) {
		System.out.println(" Stop at " + msg);
		try {
			BufferedReader read= new BufferedReader(new InputStreamReader(System.in));
			read.readLine();
		} catch (Exception ex) {
			System.out.println("In debugStop(): " + ex);
		}
	}

}
