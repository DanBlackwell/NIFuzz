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

import java.util.TreeSet;
import java.io.*;
import bham.leakiest.infotheory.*;

/**
 * This is the class for parsing command line options of the tool leakiEst.
 *
 * @author Yusuke Kawamoto
 * @author Tom Chothia
 * @author Chris Novakovic
 * @version 1.4.9
 */
public class CommandLine {
	// Version
	static String version = TestInfoLeak.version;
	
	// File type
	//static final int ChanFile = 1; 

	// Constants on task types
	static final int CLC_MUTUAL_INFO = TestInfoLeak.CLC_MUTUAL_INFO;
	static final int CLC_CAPACITY = TestInfoLeak.CLC_CAPACITY;
	static final int CLC_MIN_ENTROPY = TestInfoLeak.CLC_MIN_ENTROPY;
	static final int CLC_MIN_CAPACITY = TestInfoLeak.CLC_MIN_CAPACITY;
	static final int CLC_G_LEAK = TestInfoLeak.CLC_G_LEAK;
	
	// Constants on file types
	static final int READ_CFG = TestInfoLeak.READ_CFG;
	static final int READ_ERROR = TestInfoLeak.READ_ERROR;
	static final int READ_ARFF = TestInfoLeak.READ_ARFF;
	static final int READ_CH = TestInfoLeak.READ_CH;
	static final int READ_OBS1 = TestInfoLeak.READ_OBS1;
	static final int READ_OBS2 = TestInfoLeak.READ_OBS2;
	static final int READ_PRIOR = TestInfoLeak.READ_PRIOR;
	static final int READ_GUESS = TestInfoLeak.READ_GUESS;
	
	// Constants relating to automatic termination
	// after corrected leakage stabilises
	//static final int LEAKAGE_STABILISATION_INITIAL_INTERVAL = 100; // the initial number of samples to read before creating the first and second intervals
	//static final double LEAKAGE_STABILISATION_DELTA = 0.01; // if leakages at successive intervals differ by less than this amount, terminate
	
	// Other constants
	static final double ERROR = TestInfoLeak.ERROR;
	static final double UNKNOWN = TestInfoLeak.UNKNOWN;
	static final double APPROX_OPTIMIZED = TestInfoLeak.APPROX_OPTIMIZED;

	// Features for high values
	TreeSet<Integer> highFeatures = TestInfoLeak.highFeatures;
	TreeSet<String> highFeaturesSet = TestInfoLeak.highFeaturesSet;

	// Features for low values
	TreeSet<Integer> lowFeatures = TestInfoLeak.lowFeatures;
	TreeSet<String> lowFeaturesSet = TestInfoLeak.lowFeaturesSet;

	// Checking each feature for low values (or not)
	boolean checkEachFeature = TestInfoLeak.checkEachFeature;

	// Default options (that can be override by the commandline).
	boolean readFromChanFile = TestInfoLeak.readFromChanFile;
	boolean readFromCfgFile = TestInfoLeak.readFromCfgFile;
	boolean readFromObsFile = TestInfoLeak.readFromObsFile;
	boolean readFrom2ObsFiles = TestInfoLeak.readFrom2ObsFiles;
	boolean readFromARFFFile = TestInfoLeak.readFromARFFFile;
	boolean readFromPriorFile = TestInfoLeak.readFromPriorFile;
	boolean readFromGuessFile = TestInfoLeak.readFromGuessFile;
	boolean ignoreOptionDis = TestInfoLeak.ignoreOptionDis;
	boolean ignoreOptionCfg = TestInfoLeak.ignoreOptionCfg;
	boolean ignoreOptionDir = TestInfoLeak.ignoreOptionDir;
	boolean ignoreOptionIn = TestInfoLeak.ignoreOptionIn;
	boolean ignoreOptionOut = TestInfoLeak.ignoreOptionOut;
	boolean ignoreOptionPrior = TestInfoLeak.ignoreOptionPrior;
	boolean ignoreOptionGuess = TestInfoLeak.ignoreOptionGuess;
	boolean ignoreOptionNOCR = TestInfoLeak.ignoreOptionNOCR;
	boolean ignoreOptionAPPROX = TestInfoLeak.ignoreOptionAPPROX;
	boolean ignoreOptionAJS  = TestInfoLeak.ignoreOptionAJS;
	boolean ignoreOptionPM = TestInfoLeak.ignoreOptionPM;
	boolean ignoreOptionPJ = TestInfoLeak.ignoreOptionPJ;
	boolean ignoreOptionCSV = TestInfoLeak.ignoreOptionCSV;
	boolean ignoreOptionTerminate = TestInfoLeak.ignoreOptionTerminate;
	int taskType = TestInfoLeak.taskType;
	boolean compositionalEstimate = TestInfoLeak.compositionalEstimate;
	boolean priorShared = TestInfoLeak.priorShared;
	boolean skipZLT = TestInfoLeak.skipZLT;
	boolean correctLeak = TestInfoLeak.correctLeak;
	boolean correctLeakNew = TestInfoLeak.correctLeakNew;
	double approxPriorLevel = TestInfoLeak.approxPriorLevel;
	boolean approxDoNotKnowChannels = TestInfoLeak.approxDoNotKnowChannels;
	boolean checkJointlySupported = TestInfoLeak.checkJointlySupported;
	int fileType = TestInfoLeak.fileType;
	boolean OBS_DISCRETE = TestInfoLeak.OBS_DISCRETE;
	boolean debugCode = TestInfoLeak.debugCode;
	
	boolean PRINT_CHANNELMATRIX = TestInfoLeak.PRINT_CHANNELMATRIX;
	boolean PRINT_JOINTMATRIX = TestInfoLeak.PRINT_JOINTMATRIX;
	public int verbose = TestInfoLeak.verbose;
	double acceptableError = TestInfoLeak.acceptableError;
	int noOfIterations = TestInfoLeak.noOfIterations;
	int noOfTestsContinuous = TestInfoLeak.noOfTestsContinuous;
    protected boolean fixMeanForPassportAnalyses = TestInfoLeak.fixMeanForPassportAnalyses; // Only used for PassportAnalyses 
    protected boolean fixMedianForPassportAnalyses = TestInfoLeak.fixMedianForPassportAnalyses; // Only used for PassportAnalyses 

	//static Observations obs;
	int numChannels = 1;
	//static Channel channel;
	Channel[] channels;
	//static ContinuousData cdata;
	int numPriors = 1;
	ProbDist[] pds;
	//static double[] inputDist;
	//static Set<String> guessDomain;
	String nameGainFunction;
	GainFunction gf;
	
	String cfgFileName = "";       // cfgFileName is set by the commandline
	String directoryName = "";     // directoryName is set by the commandline
	String dataFileName = "";      // dataFileName is set by the commandline
	String dataFileName2 = "";     // dataFileName2 is set by the commandline
	String[] dataFileNames;        // dataFileNames[] is set by the commandline
	String[] priorFileNames;       // priorFileNames[] is set by the commandline
	String guessFileName = "";     // guessFileName is set by the commandline
	int csvEstimationInterval = 0; // set by the command-line option "-csv"
	CSVFile csvFile;               // set by the command-line option "-csv"
	boolean terminateWhenStabilised = false; // set by the command-line option "-t"

	/**
	 * Constructor
	 * 
	 * @param args inputs from user
	 */
	public CommandLine(String[] args) {
		parseCommandLine(args);
	}
	
	/**
	 * The method for parsing command lines of LeakiEst.
	 * 
	 * @param args inputs from user
	 */
	public void parseCommandLine(String[] args) {
		String[] options = new String[args.length];
		
		//
		//  Read the commandline arguments
		//
		if((args.length == 0) ||
		   (args.length > 0 && (args[0].equalsIgnoreCase("help") ||
						 		args[0].equalsIgnoreCase("h") ||
						 		args[0].equalsIgnoreCase("-h") ||
						 		args[0].equalsIgnoreCase("-help") ||
						 		args[0].equalsIgnoreCase("--help")))) {
			printUsage();
			System.exit(0);
		} else if((args.length > 0) &&
				  (args[0].equalsIgnoreCase("-hcomp"))) {
			printUsageForCompositional();
			System.exit(0);
		} else if((args.length > 0) &&
				  (args[0].equalsIgnoreCase("-cfg")) ||
				  (args[0].equalsIgnoreCase("--cfg"))) {
			readFromCfgFile = true;
			if(args.length > 1) {
			   cfgFileName = args[1];
			   ReadFile cfgReader = new ReadFile(cfgFileName, verbose, "config");
			   options = cfgReader.readConfiguration();
			   ignoreOptionCfg = true;
			}
		} else if(args.length > 0) {
			File fl = new File(args[0]);
			if(fl.exists()) {
				cfgFileName = args[0];
				ReadFile cfgReader = new ReadFile(cfgFileName, verbose, "config");
				if(cfgReader.decideFileType(args[0]) == READ_CFG) {
					options = cfgReader.readConfiguration();
					ignoreOptionCfg = true;
				} else {
					options = args;
				}
			} else {
				options = args;
			}		
		} else {
			options = args;
		}
		
		int clc = 0;
		while(clc < options.length) {
		    if(options[clc] == null || options[clc].equalsIgnoreCase("")) {
		    	clc++;
		    } else if(options[clc].equalsIgnoreCase("-cfg")) {
				System.out.println("Ignored commandline option: " + options[clc]);
				System.out.println("  -cfg <fileName> must be specified as the first option.");
				clc = clc + 2;
			} else if(options[clc].equalsIgnoreCase("-dir")) {
				if(ignoreOptionDir) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
				} else {
					if(clc + 1 < options.length)
						directoryName = options[clc+1];
				}
				clc = clc + 2;
				ignoreOptionDir = true;
			} else if(options[clc].equalsIgnoreCase("-parallel")) { 
				try {
					if(ignoreOptionIn) {
						System.out.print("Ignored commandline option: " + options[clc]);
					} else {
						numChannels = Integer.parseInt(options[clc+1]);
						compositionalEstimate = true;
					}
					clc = clc + 2;
				} catch(Exception e) {
					System.out.println("Commandline error in option " + options[clc] + ".");
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-parallel-ex") || options[clc].equalsIgnoreCase("-parallel-exact")) { 
				try {
					if(ignoreOptionIn) {
						System.out.print("Ignored commandline option: " + options[clc]);
					} else {
						numChannels = Integer.parseInt(options[clc+1]);
						compositionalEstimate = false;
					}
					clc = clc + 2;
				} catch(Exception e) {
					System.out.println("Commandline error in option " + options[clc] + ".");
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-o") || options[clc].equalsIgnoreCase("-obs")) { 
				if(ignoreOptionIn) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + numChannels < options.length)
						System.out.print(" " + options[clc+numChannels]);
					System.out.println();
				} else {
					readFromObsFile = true;
					if(clc + numChannels < options.length)
						dataFileName = directoryName + options[clc+numChannels];
				}
				clc = clc + 1 + numChannels;
				ignoreOptionIn = true;
			} else if(options[clc].equalsIgnoreCase("-o2") || options[clc].equalsIgnoreCase("-obs2")) { 
				if(ignoreOptionIn) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					if(clc + 2 < options.length)
						System.out.print(" " + options[clc+2]);
					System.out.println();
				} else {
					readFrom2ObsFiles = true;
					if(clc + 1 < options.length) {
						dataFileName = directoryName + options[clc+1];
					}
					if(clc + 2 < options.length) {
						dataFileName2 = directoryName + options[clc+2];
					}
				}
				clc = clc + 3;
				ignoreOptionIn = true;
			} else if(options[clc].equalsIgnoreCase("-c") || options[clc].equalsIgnoreCase("-ch")) {
				int repeate = 0;
				if(ignoreOptionIn) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
				} else {
					readFromChanFile = true;
					//System.out.println(" numChannels    = " + numChannels);
					dataFileNames = new String[numChannels];
					channels = new Channel[numChannels];
					//System.out.println(" options.length = " + options.length);
					//System.out.println(" clc =            " + clc);
					//System.out.println(" options[" + (clc+1) + "] = " + options[clc+1]);
					//System.out.println(" options[" + (clc+2) + "] = " + options[clc+2]);
					for(int ic = 0; ic < numChannels; ic++) {
						if(repeate == 0 && clc + 1 + ic < options.length && !options[clc+1+ic].startsWith("-")) {
							dataFileNames[ic] = directoryName + options[clc+1+ic];
							//System.out.println("  options[" + (clc+1+ic) + "] = " + options[clc+1+ic]);
							//System.out.println("  dataFileNames[" + ic + "] = " + dataFileNames[ic]);
						} else if(ic > 0) {
							dataFileNames[ic] = dataFileNames[ic-1];
							//System.out.println("  dataFileNames[" + ic + "] = " + dataFileNames[ic]);
							repeate++;
						}
					}
				}
				clc = clc + 1 + numChannels - repeate;
				ignoreOptionIn = true;
			} else if(options[clc].equalsIgnoreCase("-a") || options[clc].equalsIgnoreCase("-arff")) {
				if(ignoreOptionIn) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
				} else {
					readFromARFFFile = true;
					if(clc + 1 < options.length)
						dataFileName = directoryName + options[clc+1];
				}
				clc = clc + 2;
				ignoreOptionIn = true;
			} else if(options[clc].equalsIgnoreCase("-high")) {
				try {
					String highFeaturesStr[] = options[clc+1].split(",");
					for(String hfs : highFeaturesStr) {
						try {
							highFeatures.add(Integer.parseInt(hfs));
						} catch(Exception e) {
							highFeaturesSet.add(hfs);
						}
					}
					clc = clc + 2;
				} catch(Exception e) {
					System.out.print("Commandline error in option " + options[clc] + ".");
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-low")) {
				try {
					String lowFeaturesStr[] = options[clc+1].split(",");
					for(String lfs : lowFeaturesStr) {
						try {
							if(lfs.equalsIgnoreCase("@each")) {
								checkEachFeature = true;
								break;
							} else
								lowFeatures.add(Integer.parseInt(lfs));
						} catch(Exception e) {
							lowFeaturesSet.add(lfs);
						}
					}
					clc = clc + 2;
				} catch(Exception e) {
					System.out.print("Commandline error in option " + options[clc] + ".");
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-prior") || options[clc].equalsIgnoreCase("-prior-shared")) {
				if(ignoreOptionPrior) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
				} else {
					readFromPriorFile = true;
					priorFileNames = new String[numPriors];
					pds = new ProbDist[numPriors];
					if(clc + 1 < options.length)
						priorFileNames[0] = directoryName + options[clc+1];
					if(options[clc].equalsIgnoreCase("-prior-shared")) {
						priorShared = true;
					}
				}
				clc = clc + 2;
				ignoreOptionPrior = true;
			} else if(options[clc].equalsIgnoreCase("-priors")) {
				int repeate = 0;
				if(ignoreOptionPrior) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
				} else {
					readFromPriorFile = true;
					numPriors = numChannels;
					priorFileNames = new String[numPriors];
					pds = new ProbDist[numPriors];
					//System.out.println(" options.length = " + options.length);
					//System.out.println(" clc =            " + clc);
					//System.out.println(" options[" + (clc+1) + "] = " + options[clc+1]);
					for(int ic = 0; ic < numPriors; ic++) {
						if(repeate == 0 && clc + 1 + ic < options.length && !options[clc+1+ic].startsWith("-")) {
							priorFileNames[ic] = directoryName + options[clc+1+ic];
							//System.out.println("  options[" + (clc+1+ic) + "] = " + options[clc+1+ic]);
							//System.out.println("  priorFileNames[" + ic + "] = " + priorFileNames[ic]);
						} else if(ic > 0) {
							priorFileNames[ic] = priorFileNames[ic-1];
							//System.out.println("  priorFileNames[" + ic + "] = " + priorFileNames[ic]);
							repeate++;
						}
					}
				}
				clc = clc + 1 + numChannels - repeate;
				ignoreOptionPrior = true;
			} else if(options[clc].equalsIgnoreCase("-guess")) {
				if(ignoreOptionGuess) {
					System.out.print("Ignored commandline option: " + options[clc]);
					if(clc + 1 < options.length)
						System.out.print(" " + options[clc+1]);
					System.out.println();
				} else {
					readFromGuessFile = true;
					if(clc + 1 < options.length)
						guessFileName = directoryName + options[clc+1];
				}
 				clc = clc + 2;
				ignoreOptionGuess = true;
			} else if(options[clc].equalsIgnoreCase("-ignore-hereafter")) {
				clc = options.length;
			} else if(options[clc].equalsIgnoreCase("-di")) {
				if(ignoreOptionDis) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					OBS_DISCRETE = true;
				}
				clc = clc + 1;
				ignoreOptionDis = true;
			} else if(options[clc].equalsIgnoreCase("-co")) {
				if(ignoreOptionDis) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					OBS_DISCRETE = false;
				}
				clc = clc + 1;
				ignoreOptionDis = true;
			} else if(options[clc].equalsIgnoreCase("-mi")) {
				if(ignoreOptionOut) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					taskType = CLC_MUTUAL_INFO;
				}
				clc = clc + 1;
				ignoreOptionOut = true;
			} else if(options[clc].equalsIgnoreCase("-cp")) {
				if(ignoreOptionOut) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					taskType = CLC_CAPACITY;
				}
				clc = clc + 1;
				ignoreOptionOut = true;
			} else if(options[clc].equalsIgnoreCase("-me")) {
				if(ignoreOptionOut) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					taskType = CLC_MIN_ENTROPY;
				}
				clc = clc + 1;
				ignoreOptionOut = true;
			} else if(options[clc].equalsIgnoreCase("-mc")) {
				if(ignoreOptionOut) {
					System.out.println("Ignored commandline option: " + options[clc]);
				}else {
					taskType = CLC_MIN_CAPACITY;
				}
				clc = clc + 1;
				ignoreOptionOut = true;
			} else if(options[clc].equalsIgnoreCase("-gl")) {
				if(ignoreOptionOut) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					taskType = CLC_G_LEAK;
					if(clc + 1 < options.length) {
						nameGainFunction = options[clc+1];
						gf = new GainFunction(nameGainFunction);
					}
				}
				clc = clc + 2;
				ignoreOptionOut = true;
			} else if(options[clc].equalsIgnoreCase("-skipZLT")) {
				if(ignoreOptionNOCR) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					skipZLT = true;
				}
				clc = clc + 1;
				ignoreOptionNOCR = true;
			} else if(options[clc].equalsIgnoreCase("-nocr")) {
				if(ignoreOptionNOCR) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					correctLeak = false;
				}
				clc = clc + 1;
				ignoreOptionNOCR = true;
			} else if(options[clc].equalsIgnoreCase("-oldcr")) {
				if(ignoreOptionNOCR) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					correctLeak = true;
					correctLeakNew = false;
				}
				clc = clc + 1;
				ignoreOptionNOCR = true;
			} else if(options[clc].equalsIgnoreCase("-approx")) {
				try {
					approxPriorLevel = Double.parseDouble(options[clc+1]);
					clc = clc + 2;
				} catch(Exception e) {
					System.out.println("Commandline error in option " + options[clc] + ".");
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-approx-max")) {
				approxPriorLevel = 1.0;
				clc = clc + 1;
			} else if(options[clc].equalsIgnoreCase("-approx-opt")) {
				approxPriorLevel = APPROX_OPTIMIZED;
				clc = clc + 1;
			} else if(options[clc].equalsIgnoreCase("-do-not-know-channel")) {
				approxDoNotKnowChannels = true;
				clc = clc + 1;
			} else if(options[clc].equalsIgnoreCase("-ajs")) {
				if(ignoreOptionAJS) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					checkJointlySupported = false;
				}
				clc = clc + 1;
				ignoreOptionAJS = true;
			} else if(options[clc].equalsIgnoreCase("-e")) {
				try {
					acceptableError = Double.parseDouble(options[clc+1]);
					clc = clc + 2;
				} catch(Exception e) {
					System.out.println("Commandline error in option " + options[clc] + ".");
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-i")) {
				try {
					noOfIterations = Integer.parseInt(options[clc+1]);
					clc = clc + 2;
				} catch(Exception e) {
					System.out.println("Commandline error in option " + options[clc] + ".");
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-testco")) {
				try {
					noOfTestsContinuous = Integer.parseInt(options[clc+1]);
					clc = clc + 2;
				} catch(Exception e) {
					System.out.println("Commandline error in option " + options[clc] + ".");
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-fixMean")) {
				fixMeanForPassportAnalyses = true;
				//System.out.println("-fixMean option (only for analyses of continuous passport data) is used.");
				clc = clc + 1;
			} else if(options[clc].equalsIgnoreCase("-fixMedian")) {
				fixMedianForPassportAnalyses = true;
				//System.out.println("-fixMedian option (only for analyses of continuous passport data) is used.");
				clc = clc + 1;
			} else if (options[clc].equalsIgnoreCase("-csv")) {
				if(ignoreOptionCSV) {
					System.out.println("Ignored commandline option: " + options[clc]);
					clc++;
				} else {
					try {
						csvEstimationInterval = Integer.parseInt(options[clc+1]);
						csvFile = new CSVFile(new File(directoryName + options[clc+2]));
						clc = clc + 3;
					} catch (FileNotFoundException e) {
						System.out.println("Could not write to CSV file '" + directoryName + options[clc+2] + "'.");
						System.exit(1);
					} catch (Exception e) {
						System.out.println("Commandline error in option " + options[clc] + ".");
						printUsage();
						System.exit(1);
					}
				}
				ignoreOptionCSV = true;
			} else if (options[clc].equalsIgnoreCase("-t")) {
				if (ignoreOptionTerminate) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					terminateWhenStabilised = true;
				}
				ignoreOptionTerminate = true;
				clc++;
			} else if(options[clc].equalsIgnoreCase("-p") || options[clc].equalsIgnoreCase("-pc")) {
				if(ignoreOptionPM) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					PRINT_CHANNELMATRIX = true;
				}
				clc = clc + 1;
				ignoreOptionPM = true;
			} else if(options[clc].equalsIgnoreCase("-pj")) {
				if(ignoreOptionPJ) {
					System.out.println("Ignored commandline option: " + options[clc]);
				} else {
					PRINT_JOINTMATRIX = true;
				}
				clc = clc + 1;
				ignoreOptionPJ = true;
			} else if(options[clc].equalsIgnoreCase("-v")) {
				try {
					verbose = Integer.parseInt(options[clc+1]);
					clc = clc + 2;
					//System.out.println("verbose = " + verbose);
				} catch(Exception e) {
					System.out.println("Commandline error in option " + options[clc] + ".");
					printUsage();
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-version")) {
				try {
					verbose = Integer.parseInt(options[clc+1]);
					clc = clc + 2;
					//System.out.println("verbose = " + verbose);
				} catch(Exception e) {
					System.out.println("leakiEst version " + version + ".");
					System.exit(1);
				}
			} else if(options[clc].equalsIgnoreCase("-debug")) {
				debugCode = true;
				clc++;
			} else if(options[clc].equalsIgnoreCase("-debug-overwrite-options")) {
				ignoreOptionDis = false;
				ignoreOptionCfg = false;
				ignoreOptionDir = false;
				ignoreOptionIn = false;
				ignoreOptionOut = false;
				ignoreOptionPrior = false;
				ignoreOptionGuess = false;
				ignoreOptionNOCR = false;
				ignoreOptionAPPROX = false;
				ignoreOptionAJS  = false;
				ignoreOptionPM = false;
				ignoreOptionPJ = false;
				ignoreOptionCSV = false;
				ignoreOptionTerminate = false;
				clc++;
			} else {
				File fl = new File(options[clc]);
				if(!ignoreOptionIn && fl.exists()) {
				   ReadFile testReader = new ReadFile(options[clc], verbose, "unknown");
				   fileType = testReader.decideFileType(options[clc]);
				
					if(fileType == ERROR) {
						System.out.println("Unrecognised commandline option: " + options[clc]);
						System.out.println("  Skipping it. Use -h or help for a list of options");
					} else {
						dataFileName = options[clc];
						dataFileNames = new String[1];
						dataFileNames[0] = dataFileName;
						channels = new Channel[1];
						ignoreOptionIn = true;
					}
					clc = clc + 1;
				} else {
					System.out.println("Unrecognised commandline option: " + options[clc]);
					System.out.println("  Skipping it. Use -h or help for a list of options");
					clc = clc + 1;
				}
			}
		}
		
		// If file type was not specified in the commandline, we decide the file type.
		if(!readFromChanFile && !readFromObsFile && !readFrom2ObsFiles && !readFromARFFFile && !dataFileName.equals("")) {
			switch(fileType) {
			case(READ_ARFF):
				readFromARFFFile = true;
				System.out.println("\"" + dataFileName + "\" is recognised as an ARFF file.");
				break;
			case(READ_CH):
				readFromChanFile = true;
				System.out.println("\"" + dataFileName + "\" is recognised as a channel file.");
				break;
			case(READ_OBS1):
				readFromObsFile = true;
				System.out.println("\"" + dataFileName + "\" is recognised as an observation file.");
				break;
			case(READ_OBS2):
				readFrom2ObsFiles = true;
				System.out.println("\"" + dataFileName + "\" is recognised as two observation files.");
				break;
			case(READ_ERROR):
				System.out.println("Commandline error: File name is not specified.");
				printUsage();
				System.exit(1);
			}
		}


		// Continuous option is valid only for mutual information without a channel file
		if(!OBS_DISCRETE && (taskType != CLC_MUTUAL_INFO || readFromChanFile)) {
			OBS_DISCRETE = true;
			System.out.println("Ignored commandline option: -co");
			System.out.println("  Continuous option is valid only for mutual information");
			System.out.println("  and only with either an observation file or ARFF file.");
			System.out.println("Set commandline option: -di");
		}

		// Print no channel/joint matrix in the case of continuous option
		if(!OBS_DISCRETE) {
			PRINT_CHANNELMATRIX = false;
			PRINT_JOINTMATRIX = false;
		}

		// @each must be ignored except when analysing an ARFF file
		if(!readFromARFFFile) {
			checkEachFeature = false;
		}

		// No correction of leakge results in the case where
		// the channel matrix is not estimated from samples
		if(readFromChanFile) {
			correctLeak = false;
		}

		// Parallel composition of channels is supported only for 
		// channel files (-c) and observation files (-o)
		if(compositionalEstimate && numChannels > 1 && (readFrom2ObsFiles || readFromARFFFile)) {
			System.out.println("Commandline error: Prallel composition is not supported for the options -a and -o2.");
			System.exit(1);
		}

		// If priors to channels are independent, we do not produce the joint distribution to 
		// calculate the exact leakage value of the parallel composition of channels.
		if(!compositionalEstimate && numPriors > 1) {
			compositionalEstimate = true; // we do not apply methods for exact calculation.
			if(verbose >= 5) {
				System.out.println("A compositionalility result is used to obtain the exact leakage.");
			}
		}

		// Check whether dataFileName is specified
		if(dataFileName.equals("") && (!readFromChanFile || !OBS_DISCRETE)) {
			System.out.println("Commandline error: File name is not specified.");
			printUsage();
			System.exit(1);
		}
		
		// If a CSV file is to be generated with incremental estimates of
		// leakage, make sure we're reading in a file where it makes sense to
		// calculate that information. Currently:
		// - observations file with discrete data;
		// - 2 observations files with discrete data;
		// - ARFF file with discrete data, when -low is not @each.
		// Yusuke thinks it makes sense to do this for observations files with
		// continuous data too; that'll be implemented later.
		if((csvFile != null) && !(OBS_DISCRETE && readFromObsFile) &&
		   !(OBS_DISCRETE && readFrom2ObsFiles) &&
		   !(OBS_DISCRETE && readFromARFFFile && !checkEachFeature)) {
			System.out.println("Incremental estimations of leakage can only be calculated when reading the following file types:");
			System.out.println("* Observations file containing discrete data");
			System.out.println("* 2 observations files containing discrete data");
			System.out.println("* ARFF file containing discrete data, with value of -low other than @each");
			printUsage();
			System.exit(1);
		}

		// If we have to automatically terminate when the corrected leakage
		// stabilises, we have to make sure the following conditions hold:
		// - we're measuring mutual information
		// - we're reading in discrete data
		// - we're reading in an observations file, 2 observations files, or an
		//   ARFF file when -low is not @each
		if(terminateWhenStabilised &&
		   !(taskType == CLC_MUTUAL_INFO && OBS_DISCRETE && readFromObsFile) &&
		   !(taskType == CLC_MUTUAL_INFO && OBS_DISCRETE && readFrom2ObsFiles) &&
		   !(taskType == CLC_MUTUAL_INFO && OBS_DISCRETE && readFromARFFFile && !checkEachFeature)) {
			System.out.println("Can only automatically terminate when calculating mutual information and when reading the following file types:");
			System.out.println("* Observations file containing discrete data");
			System.out.println("* 2 observations files containing discrete data");
			System.out.println("* ARFF file containing discrete data, with value of -low other than @each");
			printUsage();
			System.exit(1);
		}
	}


	/**
	 * Print usage of this tool.
	 */
	public static void printUsage() {
		System.out.println("");
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("LeakiEst");
		System.out.println("  This is a program to calculate the information leakage of a system from");
		System.out.println("  either a matrix relating the inputs and outputs, a list of observations");
		System.out.println("  of the systems, or an ARFF file.");
		System.out.println("To run type: java -jar leakiest-" + version + ".jar <configuration file name>");
		System.out.println("         or  java -jar leakiest-" + version + ".jar <options>");
		System.out.println("");
		System.out.println("[Options]");
		System.out.println("  -h, -help             output usage information");
		System.out.println("  -hcomp                output usage information on an extension to compositional reasoning");
		System.out.println("  -cfg <fileName>       read input from a configuration file <fileName>");
		System.out.println("");
		System.out.println("for inputs to the tool:");
		//System.out.println("  -dir <dirname>        specify a directory name that is part of paths of files");
		System.out.println("  -o, -obs <fileName>   read input from an observations file <fileName>");
		System.out.println("  -o2, -obs2 <fileName1> <fileName2>");
		System.out.println("                        read input from two observations files <fileName1> and");
		System.out.println("                        <fileName2> each recording the observation of one attribute.");
		System.out.println("  -c, -ch <fileName>    read input from a channel file <fileName>");
		System.out.println("  -a, -arff <fileName>  read input from an ARFF file <fileName>");
		System.out.println("  -high <numbers>       specify high value features");
		System.out.println("                            e.g. -high 1,3,4 -high Intent");
		System.out.println("  -low <numbers>        specify low value features");
		System.out.println("                            e.g. -low 12,13 -low @each -low 6 Total_Bytes_Allocated");
		System.out.println("  -prior <fileName>     specify an input distribution (or use uniform distribution)");
		System.out.println("  -ignore-hereafter     ignoring the rest of all options hereafter");
		System.out.println("");
		System.out.println("for leakage measures:");
		System.out.println("  -di                   use discrete data");
		System.out.println("  -co                   use continuous data");
		System.out.println("  -mi                   calculate mutual information");
		System.out.println("  -cp                   calculate capacity");
		System.out.println("  -me                   calculate min-entropy leakage");
		System.out.println("  -mc                   calculate min-capacity");
		System.out.println("");
		System.out.println("for accuracy of results:");
		System.out.println("  -skipZLT              skip the zero leakage test (only for -co -mi)");
		System.out.println("  -nocr                 do not correct the leakage value");
		System.out.println("  -oldcr                use old correction method");
		System.out.println("  -e <level>            set the acceptable error level for Blahut-Arimoto Algorithm");
		System.out.println("                            e.g. -e 0.0000001");
		System.out.println("  -i <number>           set the maximum number of interations  e.g. -i 500");
		System.out.println("  -testco <number>      set the number of zero leak tests for continuous MI  e.g. -testco 100");
		//System.out.println("  -fixMean              fix the mean of continuous data in the case of passport analyses");
		//System.out.println("  -fixMedian            fix the median of continuous data in the case of passport analyses");
		System.out.println("");
		System.out.println("for outputs of results:");
		System.out.println("  -csv <i> <fileName>   write a CSV file <fileName> containing intermediate estimations");
		System.out.println("                            of leakage, calculating the estimations at intervals of <i>");
		System.out.println("                            observations (requires one of -o, -o2, or -a with a value");
		System.out.println("                            of -low other than @each)");
		System.out.println("  -t                    terminate when the corrected leakage value stabilises (requires");
		System.out.println("                            -di, -mi, and one of -o, -o2, or -a with a value of -low");
		System.out.println("                            other than @each, and does not give an optimal result.)");
		System.out.println("  -p, -pc               print a channel matrix");
		System.out.println("  -pj                   print a joint distribution matrix");
		System.out.println("  -v <level>            set the level of information shown (0 to 5)  e.g. -v 4");
		System.out.println("  -version              print the version of this tool");
	}
	
	
	/**
	 * Print usage of this tool concerning an exntension to compositionality (using results in QEST 2014).
	 */
	public static void printUsageForCompositional() {
		System.out.println("");
		System.out.println("-------------------------------------------------------------------------");
		System.out.println("Extension of LeakiEst to compositional reasoning");
		System.out.println("(These options are not maintained since version 1.3.0)");
		System.out.println("");
		System.out.println("[Options]");
		System.out.println("for inputs to the tool:");
		System.out.println("  -parallel <number>    calculate the leakage bounds on the parallel");
		System.out.println("                            composition of <number> channels");
		System.out.println("  -parallel-ex <number> calculate the exact leakage of the parallel");
		System.out.println("                            composition of <number> channels");
		System.out.println("  -priors <fileNames>   specify any number of independent input distributions");
		System.out.println("                            (or use uniform distribution)");
		System.out.println("  -prior-shared <fileName>  specify an input distribution (or use uniform");
		System.out.println("                            distribution) whose identical input value is shared");
		System.out.println("                            among all channels");
		System.out.println("  -approx               approximate the input distribution to calulcate a measure");
		System.out.println("  -do-not-know-channel  calculate the leakage bounds that the analyzer can obtain");
		System.out.println("                            by a compositional reasoning using the given input");
		System.out.println("                            distribution, without knowing the channels");
		System.out.println("  -ajs                  assume the input distribution is jointly supported and do");
		System.out.println("                        not check it");
		System.out.println("");
		System.out.println("for g-leakage calculation (only partially supported):");
		System.out.println("  -gl                   calculate g-leakage");
		System.out.println("  -guess <fileName>     specify a set of all possible guesses on inputs");
	}
}
