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
 * Copyright 2013 Tom Chothia, Yusuke Kawamoto and Chris Novakovic
 */
package bham.leakiest;

import java.io.*;
import java.util.ArrayList;
import java.util.TreeSet;
import java.util.regex.*;
import java.util.Vector;

/**
 * This is the class that contains methods for reading a conditional probability
 * matrix or a list of observations from a text file.
 * 
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.2
 */
public class ReadFile {
	int noOfInputs;
	String[] outputNames; 
    String[] inputNames;       
    double[][] channelMatrix; 
    Observations obs;
    ProbDist pd;
    TreeSet<String> guessDomain;
    int noOfGroups;
    String[] groupNames;
    int[] groupForRow;
	Vector[] rowsForGroup;
    // boolean multiSender;
    // inputsPerRow is a vector of vectors. 
    // inputPerRow.get(i) are the indexes of the inputs 
    // on row i of the channel matrix 
	Vector<Vector<Integer>> inputsPerRow = new Vector<Vector<Integer>>();
    Channel channel;
    String fileName;
    String fileName2;
    private int verbose = 3;
    private int csvInterval;
    private CSVFile csvFile;
    private boolean terminateWhenStabilised = false;

    ContinuousData cdata;
    //private boolean fixDataForPassportAnalyses = false; // Only used for PassportAnalyses 

    
    /**
     * Sets a file name for input.
     * @param inputFileName File name for input
     * @param v verbose
     * @param comment comment on the data file
     */
    public ReadFile(String inputFileName, int v, String comment) {
    	if(inputFileName == null) {
    		System.out.println("Error: No file name (for " + comment + ") is specifed correctly.");
    		System.exit(1);
    	}
    	fileName = removeQuotation(inputFileName);
    	verbose = v;
    	if(verbose > 3)
    		System.out.println("Loading data (" + comment + ") from " + inputFileName + "...");
    }
    
    /**
     * Reads the contents of a file into an Observations object in increments of
     * a given number of lines.
     * @param inputFileName File name for input
     * @param v Verbosity level
     * @param csvInterval Number of lines to read from the file during each
     * increment
     * @param csvFile The CSV file to write intermediate leakage estimates to
     */
    public ReadFile(String inputFileName, int v, int csvInterval, CSVFile csvFile) {
    	if(inputFileName == null) {
    		System.out.println("Error: No file name is specifed correctly.");
    		System.exit(1);
    	}
    	fileName = removeQuotation(inputFileName);
    	verbose = v;
    	this.csvInterval = csvInterval;
    	this.csvFile = csvFile;
    	if(verbose > 3)
    		System.out.println("Loading data from " + inputFileName + " in increments of " + csvInterval + " lines...");
    }

    /**
     * Sets two file names for input.
     * @param inputFileName1 File name for input
     * @param inputFileName2 File name for input
     * @param v verbose
     * @param comment comment on the data file
     */
    public ReadFile(String inputFileName1, String inputFileName2, int v, String comment) {
    	if(inputFileName1 == null || inputFileName2 == null) {
    		System.out.println("Error: No file names (for " + comment + ") are specifed correctly.");
    		System.exit(1);
    	}
    	fileName = removeQuotation(inputFileName1);
    	fileName2 = removeQuotation(inputFileName2);
    	verbose = v;
    	if(verbose > 3) {
    		System.out.println("Loading data (" + comment + ") from " + fileName + " and " + fileName2 + "...");
    	}
    }
    
    /**
     * Reads the contents of two files into an Observations object in increments
     * of a given number of lines.
     * @param inputFileName1 File name for input
     * @param inputFileName2 File name for input
     * @param v Verbosity level
     * @param csvInterval Number of lines to read from the file during each
     * increment
     * @param csvFile The CSV file to write intermediate leakage estimates to
     */
    public ReadFile(String inputFileName1, String inputFileName2, int v, int csvInterval, CSVFile csvFile) {
    	if(inputFileName1 == null || inputFileName2 == null) {
    		System.out.println("Error: No file names are specifed correctly.");
    		System.exit(1);
    	}
    	fileName = removeQuotation(inputFileName1);
    	fileName2 = removeQuotation(inputFileName2);
    	verbose = v;
    	this.csvInterval = csvInterval;
    	this.csvFile = csvFile;
    	if(verbose > 3) {
    		System.out.println("Loading data from " + inputFileName1 + " and " + inputFileName2 + " in increments of " + csvInterval + " lines...");
    	}
    }
    
    /**
     * Controls whether the <tt>readObservations()</tt> and
     * <tt>read2DiscreteObservationsFiles()</tt> methods should terminate before
     * they have finished reading all of the available samples, if the corrected
     * leakage value stabilises.
     * @param flag <tt>true</tt> to terminate early; <tt>false</tt> to read all
     * of the samples regardless.
     */
    public void setTerminateWhenStabilised(boolean flag) {
    	terminateWhenStabilised = flag;
    	if (flag && verbose > 3) System.out.println("Samples will stop being read when the corrected leakage value stabilises.");
    }

    /**
     * Removes quotation marks from a string.
     * 
     * @param inputFileName File name string
     * @return File name string without quotation marks
     */
    public String removeQuotation(String inputFileName) {
    	if(( inputFileName.startsWith("\"") || inputFileName.startsWith("\'") || inputFileName.startsWith("`") ) &&
    	   ( inputFileName.endsWith("\"") || inputFileName.endsWith("\'") || inputFileName.startsWith("`") ))
    		return inputFileName.substring(1, inputFileName.length()-1);
    	else
    		return inputFileName;
    }


    /**
     * Returns the channel.
     * 
     * @return channel
     */
    public Channel getChannel() {
    	return channel;
    }

    /**
     * Returns the observation.
     * 
     * @return Observation
     */
    public Observations getObservations() {
    	return obs;
    }
    

    /**
     * Returns the distribution.
     * 
     * @return ProbDist
     */
    public ProbDist getDistribution() {
    	return pd;
    }
    

    /**
     * Returns the set of all guesses.
     * 
     * @return the set of all guesses
     */
    public TreeSet<String> getGuessDomain() {
    	return guessDomain;
    }
    

    /**
	 * Reads a configuration file.
     * 
     * @return array of options that are provided to this tool
     */
	public String[] readConfiguration() {
    	String[] optionsArray;
    	ArrayList<String> optionsList = new ArrayList<String>();
	    try {
	    	BufferedReader reader =  new BufferedReader(new FileReader(fileName));
			String line;
			while(( line = reader.readLine()) != null ) {
				if(!((line.trim()).equalsIgnoreCase("") ||
					 (line.trim()).startsWith("//"))) {
					String[] splitedLine = line.split(" ",-1);
					for(String str : splitedLine) {
						if(!str.trim().equalsIgnoreCase("")) {
							optionsList.add(removeQuotation(str.trim()));
					    	//System.out.println("  [" + str.trim() + "]");
						}
					}
				}
			}
	    } catch(FileNotFoundException e) {
	    	System.out.println("Configuration file " + fileName + " not found.");
			System.exit(1);
	    } catch(Exception e) {
	    	System.out.println("Error in reading the configuration file.");
	    	System.out.println("  The file does not follow a configuration (-cfg) format.");
			e.printStackTrace();
			System.exit(1);
	    }
    	optionsArray = (String[])optionsList.toArray(new String[0]);
    	
   	    //for(String str : optionsArray)
    	//	System.out.println(str);
    	return optionsArray;
    }

    
    /**
	 * Decides the file type of a given data file.
     * If it hasn't been specified on the command line,
     * find out if the file is a matrix or observations.
	 * 
	 * @param dataFileName the file name of a given data file
	 * @return file type of a given data file
	 */
	public int decideFileType(String dataFileName) {
		int fileType = TestInfoLeak.READ_ERROR;
		try {
			if(verbose > 3)
				System.out.println("Checking the file type...");

			BufferedReader reader =  new BufferedReader(new FileReader(dataFileName));
			String line = reader.readLine();

			// Patter match for configuration files
			Pattern patternCFG = Pattern.compile("^//CFG");	
			Matcher matcherCFG = patternCFG.matcher(line);

			while( (line.trim()).equalsIgnoreCase("") || (line.trim()).startsWith("//")) {
				line = reader.readLine();
			}
			
			// Patter match for ARFF files
			Pattern patternARFF = Pattern.compile("@relation ([\\S]+)");	
			Matcher matcherARFF = patternARFF.matcher(line);

			// Patter match for channel files
    		//String[] terms = line.split("\\|");
    		//Pattern patternCh1 = Pattern.compile("\\([\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*\\)[\\s]*:[\\s]*([\\d]+)*[\\s]*");
    		Pattern patternCh1 = Pattern.compile("\\([\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*\\)[\\s]*:[\\s]*([\\d]+)*[\\s]*[\\s]*\\|");
    		//Matcher matcherCh1 = patternCh1.matcher(terms[0].trim());
    		Matcher matcherCh1 = patternCh1.matcher(line);
			//Pattern patternCh2 = Pattern.compile("\\([\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*\\)");
			Pattern patternCh2 = Pattern.compile("\\([\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*\\)[\\s]*\\|");
			//Matcher matcherCh2 = patternCh2.matcher(terms[0].trim());
			Matcher matcherCh2 = patternCh2.matcher(line);
			
			// Patter match for observation files
			line = reader.readLine();
			Pattern patternObs = Pattern.compile("\\([\\s]*([\\.\\w:]+)[\\s]*,[\\s]*([\\.\\w]+)[\\s]*\\)");
			Matcher matcherObs = patternObs.matcher(line.trim());
			
			if(matcherCFG.find()){
				fileType = TestInfoLeak.READ_CFG;
			} else if(matcherARFF.find()){
				fileType = TestInfoLeak.READ_ARFF;
			} else if(matcherCh1.find() || matcherCh2.find()) {
				fileType = TestInfoLeak.READ_CH;
			} else if(matcherObs.find()) {
				fileType = TestInfoLeak.READ_OBS1;
			}
			reader.close();
		} catch(IOException e) {
			System.out.println("Error in trying to read the file: " + dataFileName);
			System.exit(1);
		}
		return fileType;
	}
	
    /**
	 * Reads a channel file.
     */
    @SuppressWarnings("unchecked")
	public void readChannel() {
	    try {
	    	BufferedReader reader =  new BufferedReader(new FileReader(fileName));
	    	try {
	    		String line = reader.readLine();	
	    		while ( (line.trim()).equalsIgnoreCase("") || (line.trim()).startsWith("//"))
	        		line = reader.readLine();

	    		channel = new Channel();
	        
	    		String[] terms = line.split("\\|");
	    		Pattern pattern = Pattern.compile("\\([\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*\\)[\\s]*:[\\s]*([\\d]+)*[\\s]*");
	    		Matcher matcher = pattern.matcher(terms[0].trim());

	    		if(matcher.find()) {
  			  		// It's a conditional channel.
  			  		channel.kind = Channel.COND;
  			  
  			  		int noOfInputs = Integer.parseInt(matcher.group(1));
  			  		int noOfOutputs = Integer.parseInt(matcher.group(2));
  			  		int noOfGroups = Integer.parseInt(matcher.group(3));
    	     
  			  		outputNames = new String[noOfOutputs];
  			  		inputNames = new String[noOfInputs];           	 
  			  		groupNames = new String[noOfGroups];
  			    
  			  		channelMatrix = new double[noOfInputs][noOfOutputs];
  			  		groupForRow = new int[noOfInputs];
	        	
  			  		rowsForGroup = new Vector[noOfGroups];
  			  		for(int i = 0; i < noOfGroups; i++) {
  			  			rowsForGroup[i] = new Vector();
  			  		}
  			  	
  			  		// Read the output names from along the top of the matrix
  			  		for(int i = 1; i < terms.length; i++) {
  			  			outputNames[i-1] = terms[i].trim();
  			  		}
  			  		channel.setOutputNames(outputNames);
	        	
  			  		// Read the rest of the matrix one line at a time
  			  		int linecounter = 0;
  			  		while(( line = reader.readLine()) != null) {
  			  			if(!(line.trim()).equalsIgnoreCase("") && !(line.trim()).startsWith("//") ) {	        			
  			  				terms = line.split("\\|");
  			  				String[] rowlabel = terms[0].split(":");
  			  				inputNames[linecounter] = rowlabel[0].trim();

  			  				int groupIndex = addifnew(rowlabel[1].trim(),groupNames);
  			  			
  			  				groupForRow[linecounter] = groupIndex;
	        			
  			  				rowsForGroup[groupIndex].add(new Integer(linecounter));
  			  			
  			  				for(int i = 1; i < terms.length; i++) {
  			  					channelMatrix[linecounter][i-1] = Double.parseDouble(terms[i].trim());
  			  				}
  			  				linecounter++;
  			  			}
  			  		}
  			  		channel.setRowsForGroup(rowsForGroup);
  			  		channel.setGroupForRow(groupForRow);
  			  		channel.setInputNames(inputNames);
  			  		channel.setMatrix(channelMatrix);
  			  		channel.setOutputNames(outputNames);
  			  		channel.setGroupNames(groupNames);			  
	    		} else {
	    			pattern = Pattern.compile("\\([\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*\\)");
	    			matcher = pattern.matcher(terms[0].trim());
	    			
	    			if(matcher.find()) {
	    				// It's a basic channel
	    				channel.kind = Channel.BASIC;
	        	
	    				int noOfInputs = Integer.parseInt(matcher.group(1));
	    				int noOfOutputs = Integer.parseInt(matcher.group(2));
	     
	    				outputNames = new String[noOfOutputs];
	    				inputNames = new String[noOfInputs];           	        
	    				channelMatrix = new double[noOfInputs][noOfOutputs];
	        
	    				// Read the output names from along the top of the matrix
	    				for(int i = 1; i < terms.length; i++) {
	    					outputNames[i-1] = terms[i].trim();
	    				}
	    				channel.setOutputNames(outputNames);
	        	
	    				// Read the rest of the matrix one line at a time
	    				int linecounter = 0;
	    				while(( line = reader.readLine()) != null) {
	    					if(!(line.trim()).equalsIgnoreCase("") && !(line.trim()).startsWith("//") ) {	        			
	    						terms = line.split("\\|");
		    					if(linecounter >= noOfInputs) {
		    				    	System.out.println("Error in reading line " + (linecounter+1) +" in the channel file.");
		    				    	System.out.println("  The size of the matrix is specified incorrectly.");
		    				    	System.out.println("  noOfInputs (specified size)   = " + noOfInputs);
		    				    	System.out.println("  line                          = " + line);
		    					}
	    						if(terms.length -1 > noOfOutputs) {
		    				    	System.out.println("Error in reading line " + (linecounter+1) +" in the channel file.");
		    				    	System.out.println("  The size of the matrix is specified incorrectly.");
		    				    	System.out.println("  noOfOutputs (specified size)  = " + noOfOutputs);
		    				    	System.out.println("  number of columns in the file = " + (terms.length-1));
	    						}
	    						inputNames[linecounter] = terms[0].trim();
	    						for(int i = 1; i < terms.length; i++) {
	    							channelMatrix[linecounter][i-1] = Double.parseDouble(terms[i].trim());
	    						}
	    						linecounter++;
	    					}
	    				}
	    				channel.setInputNames(inputNames);
	    				channel.setMatrix(channelMatrix);
	    			} else {
	    				pattern = Pattern.compile("\\([\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*,[\\s]*([\\d]+)[\\s]*\\)*");	
	    				matcher = pattern.matcher(terms[0].trim());
	    				if(matcher.find()) {
	    					// Channel is a multi-access channel
	    					channel.kind = Channel.MULTI;
	        		
	    					String[] arrayOfInputs;
	    					outputNames = new String[Integer.parseInt(matcher.group(3))];
	    					inputNames = new String[Integer.parseInt(matcher.group(1))];
	    					channelMatrix = new double[Integer.parseInt(matcher.group(2))][Integer.parseInt(matcher.group(3))];
	      	   
	    					// Read the output names from along the top of the matrix
	    					for(int i= 1;i<terms.length;i++)
	    						outputNames[i-1] = terms[i].trim();
	    					channel.setOutputNames(outputNames);
	      	   
	    					// Read the rest of the matrix one line at a time
	    					int rowCounter = 0;
	    					while(( line = reader.readLine()) != null) {
	    						if(!(line.trim()).equalsIgnoreCase("") && !(line.trim()).startsWith("//") ) {
	    							terms = line.split("\\|");
	    							arrayOfInputs = terms[0].split(",");    		
	    							// change all the strings to their index's inNames
	    							//  add a new entry to inNames if needed
	    							//  then add the indexes to inputsPerRow[linecounter]
	    							Vector<Integer> inputIndexRowVector = new Vector<Integer>();
	    							if(!arrayOfInputs[0].trim().equals("")) {
	    								for(int ic = 0; ic < arrayOfInputs.length; ic++) {
	    									// look up the index of arrayOfInputs[ic]
	    									int inputIndex = 0;
	    									while(inputNames[inputIndex] != null &&
	    										  !(inputNames[inputIndex].equals(arrayOfInputs[ic].trim())))
	    										inputIndex++;
	    									if(inputNames[inputIndex] == null)
	    										inputNames[inputIndex] = arrayOfInputs[ic].trim();
	    									// inputIndex is the index of arrayOfInputs[ic]
	    									inputIndexRowVector.add(new Integer(inputIndex));
	    								}
	    							}      		
	    							inputsPerRow.add(inputIndexRowVector);
	    							for(int i = 1; i < terms.length; i++)
	    								channelMatrix[rowCounter][i-1] = Double.parseDouble(terms[i].trim());
	    							rowCounter++;
	    						}
	    					}
	    					channel.setInputNames(inputNames);
	    					channel.setInputsPerRow(vectorVectorToArrayVector(inputsPerRow));
	    					channel.setMatrix(channelMatrix);
	      	      		} else {
	      	      			// The file has the wrong format
	      	      			System.out.println("Syntax error while reading line: "+line);
	      	      			System.out.println("  File should start with a term of the form (noOfInputs,noOfOutputs),"); 
	      	      			System.out.println("  (noOfInputs,noOfOutputs):noOfGroups or (noOfInputs,noOfRows,noOfOutputs)"); 
	      	      			System.out.println("  The file does not follow a channel file (-c) format.");
	      	      			System.exit(0);
	      	      		}
	    			}
	    		}
	    	} finally {
	    		reader.close();
	    	}
	    } catch(FileNotFoundException ex) {
	    	System.out.println("Channel file not found: " + fileName);
		    System.exit(1);
		} catch(Exception ex) {
	    	System.out.println("Error in reading the channel file.");
	    	System.out.println("  The file does not follow a channel file (-c) format.");
			ex.printStackTrace();
			System.exit(1);
		}
    }
	
    
    /*
     * @param str
     * @param strs
     * @return
     */
    private int addifnew(String str, String[] strs) {
    	int i;
    	for(i = 0; i < strs.length; i++) {
    		if (strs[i] == null) {
    			strs[i]=str;
    			break;
    		}
    		if (strs[i].equals(str))
    			break;
    	}
    	return i;
    }

    
    /**
     * Converts a vector of vectors to an array of vectors. 
     * 
     * @param v vector of vectors
     * @return array of vectors
     */
	public static Vector[] vectorVectorToArrayVector(Vector<Vector<Integer>> v) {
    	Vector[] result = new Vector[v.size()]; 
    	for(int i = 0; i < v.size(); i++) {
    		result[i] = (v.get(i));
    	}
    	return result;
    }


	/**
	 * Reads a discrete observation file.
	 */
	public void readObservations() {
		obs = new Observations();
		try {
			BufferedReader input =  new BufferedReader(new FileReader(fileName));
			try {
			//	Pattern pattern = Pattern.compile("\\([\\s]*([\\w:]+)[\\s]*,[\\s]*([\\w:]+)[\\s]*\\)");
				Pattern pattern = Pattern.compile("\\([\\s]*([\\.\\w\\W:]+)[\\s]*,[\\s]*([\\.\\w\\W]+)[\\s]*\\)");
				Matcher matcher;
				String line;
				int lineNumber = 1;
				
				boolean leakageStabilised = false;
				double correctedLeakageFirstInterval = Double.NaN, correctedLeakageSecondInterval = Double.NaN;
				int nextLeakageInterval = TestInfoLeak.LEAKAGE_STABILISATION_INITIAL_INTERVAL;
				
				while (!leakageStabilised && (line = input.readLine()) != null) {
					matcher = pattern.matcher(line.trim());
					if (!matcher.find()) System.out.println("Syntax error while reading line: " + line);
					
					obs.addObservation(matcher.group(1), matcher.group(2));
					
					// If we've now read in the number of lines necessary to do
					// an intermediate leakage calculation, do it now
					if (csvInterval != 0 && lineNumber % csvInterval == 0) {
						csvFile.addLeakageData(obs, TestInfoLeak.taskType);
					}
					
					// If we're terminating after the leakage stabilises, and if
					// we've reached an interval where we need to check whether
					// the leakage has changed, check now
					if (terminateWhenStabilised && lineNumber == nextLeakageInterval) {
						nextLeakageInterval += 2 * (obs.getUniqueInputCount() * obs.getUniqueOutputCount());
						
						// If we don't have a first corrected leakage value yet,
						// set it to be the current corrected leakage value and
						// set the second one after another 2i*2o samples have
						// been read
						if (Double.isNaN(correctedLeakageFirstInterval)) {
							correctedLeakageFirstInterval = Estimate.getCorrectedMutualInformation(obs);
							if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by > %s, checking again after %d samples\n", lineNumber, correctedLeakageFirstInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA), nextLeakageInterval);
							
						// Otherwise, store the current corrected leakage value
						// as the second corrected leakage value and compare it
						// to the first -- if the leakage differs by more than
						// STABILISATION_DELTA then keep going and set another
						// interval for 2(i*o) samples' time; otherwise, stop
						} else {
							correctedLeakageSecondInterval = Estimate.getCorrectedMutualInformation(obs);
							
							if (Math.abs(correctedLeakageSecondInterval - correctedLeakageFirstInterval) <= TestInfoLeak.LEAKAGE_STABILISATION_DELTA) {
								if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by <= %s, not reading any more samples\n", lineNumber, correctedLeakageSecondInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA));
								leakageStabilised = true;
							} else {
								if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by > %s, checking again after %d samples\n", lineNumber, correctedLeakageSecondInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA), nextLeakageInterval);
								correctedLeakageFirstInterval = correctedLeakageSecondInterval;
							}
						}
					}
						
					lineNumber++;
				}
			} catch(Exception ex) {
				if (verbose >= 5) ex.printStackTrace();
		    	System.out.println("Error in reading the observation file: " + fileName);
		    	System.out.println("  The file does not follow an observation file (-o) format.");
				System.exit(1);
			}
			finally {
				input.close();
			}
	    } catch(FileNotFoundException ex) {
		     System.out.println("Observation file not found:" + fileName);
		     System.out.println("Failed to read a discrete observation file.");
		     System.exit(1);
		} catch(Exception ex) {
	    	System.out.println("Error in reading the observation file: " + fileName);
	    	System.out.println("  The file might not follow an observation file (-o) format.");
			//ex.printStackTrace();
			System.exit(1);
	   }
	}


	/**
	 * Reads a continuous observation file.
	 */
	public void readContinuousObservations() {
		obs = new Observations();
		cdata = new ContinuousData();
		try {
			BufferedReader input =  new BufferedReader(new FileReader(fileName));

			// Crate cdata array
			ArrayList<ArrayList<Double>> tmpDataList = new ArrayList<ArrayList<Double>>();

			try {
				Pattern pattern = Pattern.compile("\\([\\s]*([\\.\\w:]+)[\\s]*,[\\s]*([\\.\\w]+)[\\s]*\\)");
				Matcher matcher;
				String line;
				
				while(( line = input.readLine()) != null ) {
					matcher = pattern.matcher(line.trim());
					if (!matcher.find())
						System.out.println("Syntax error  while reading line: " + line);
					String instr = matcher.group(1);
					String outstr = matcher.group(2);
					obs.addObservation(instr, outstr);

					// Add a list for a new instr
					while(tmpDataList.size() < obs.getUniqueInputCount()) {
						ArrayList<Double> ald = new ArrayList<Double>();
						tmpDataList.add(ald);
					}

					// Check to see if the instr has an index in obs.intputNames
					int inputIndex = 0;
					boolean foundInput = false;
					while(inputIndex < obs.getUniqueInputCount() && !foundInput) {
						if( ((String) obs.getInputNames()[inputIndex]).equals(instr) ) {
							tmpDataList.get(inputIndex).add(Double.parseDouble(outstr));
							foundInput = true;
						} else {
							inputIndex++;
						}
					}
				}
			} catch(Exception ex) {
		    	System.out.println("Error in reading the observation file: " + fileName);
		    	System.out.println("  The file does not follow an observation file (-o) format.");
		    	System.exit(1);
			}
			finally {
				input.close();
			}
			
			// Convert the array lists to arrays
			for(ArrayList<Double> ald : tmpDataList) {
				double[] tmp = new double[ald.size()];
				for(int i = 0; i < ald.size(); i++) {
					tmp[i] = ald.get(i);
				}
				cdata.DataList.add(tmp);
			}
	    } catch(FileNotFoundException ex) {
		     System.out.println("Observation file not found:" + fileName);
		     System.out.println("Failed to read a continuous observation file.");
		     System.exit(1);
		} catch(Exception ex) {
	    	System.out.println("Error in reading the continuous observation file: " + fileName);
	    	System.out.println("  The file might not follow an observation file (-o) format.");
	    	System.out.println("  or does not contain continuous data");
			//ex.printStackTrace();
			System.exit(1);
	   }
	}


	/**
	 * Reads two discrete observation files.
	 */	
	public void read2DiscreteObservationsFiles() {
		obs = new Observations();
		String line;
		int totalLines = 1;
		
		try {
			// Read in the observations files line by line and add their data to
			// the Observations object, alternating between the two files -- the
			// input string is the name of the file
			BufferedReader reader1 = new BufferedReader(new FileReader(fileName));
			BufferedReader reader2 = new BufferedReader(new FileReader(fileName2));
			BufferedReader[] readers = { reader1, reader2 };
			String[] fileNames = { fileName, fileName2 };
			int activeBuffer = 0; // 0 = reading from reader1, 1 = reading from reader2
			boolean switchBuffers = true; // this gets set to false when one of the buffers runs out of lines
			
			boolean leakageStabilised = false;
			double correctedLeakageFirstInterval = Double.NaN, correctedLeakageSecondInterval = Double.NaN;
			int nextLeakageInterval = TestInfoLeak.LEAKAGE_STABILISATION_INITIAL_INTERVAL;
			
			try {
				while (!leakageStabilised) {
					// Read the next line from the active buffer
					line = readers[activeBuffer].readLine();
					
					if (line == null) {
						// If this line is empty and we're allowed to switch
						// buffers, read in the remaining lines from the other
						// buffer
						if (switchBuffers) {
							activeBuffer = (activeBuffer == 0 ? 1 : 0);
							switchBuffers = false;
						// If we can't switch buffers, we've now read in all the
						// lines from both buffers, so stop
						} else {
							break;
						}
					} else {
						obs.addObservation(fileNames[activeBuffer], line);
						//System.out.println("DEBUG: obs #" + totalLines + ": " + fileNames[activeBuffer] + " -> " + line);
						
						// If we've now read in the number of lines necessary to
						// do an intermediate leakage calculation, do it now
						if (csvInterval != 0 && totalLines % csvInterval == 0) {
							csvFile.addLeakageData(obs, TestInfoLeak.taskType);
						}
						
						// If we're terminating after the leakage stabilises, and if
						// we've reached an interval where we need to check whether
						// the leakage has changed, check now
						if (terminateWhenStabilised && totalLines == nextLeakageInterval) {
							nextLeakageInterval += 2 * (obs.getUniqueInputCount() * obs.getUniqueOutputCount());
							
							// If we don't have a first corrected leakage value yet,
							// set it to be the current corrected leakage value and
							// set the second one after another 2i*2o samples have
							// been read
							if (Double.isNaN(correctedLeakageFirstInterval)) {
								correctedLeakageFirstInterval = Estimate.getCorrectedMutualInformation(obs);
								if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by > %s, checking again after %d samples\n", totalLines, correctedLeakageFirstInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA), nextLeakageInterval);
									
							// Otherwise, store the current corrected leakage value
							// as the second corrected leakage value and compare it
							// to the first -- if the leakage differs by more than
							// STABILISATION_DELTA then keep going and set another
							// interval for 2(i*o) samples' time; otherwise, stop
							} else {
								correctedLeakageSecondInterval = Estimate.getCorrectedMutualInformation(obs);
								
								if (Math.abs(correctedLeakageSecondInterval - correctedLeakageFirstInterval) <= TestInfoLeak.LEAKAGE_STABILISATION_DELTA) {
									if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by <= %s, not reading any more samples\n", totalLines, correctedLeakageSecondInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA));
									leakageStabilised = true;
								} else {
									if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by > %s, checking again after %d samples\n", totalLines, correctedLeakageSecondInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA), nextLeakageInterval);
									correctedLeakageFirstInterval = correctedLeakageSecondInterval;
								}
							}
						}
						
						// Alternate to the next buffer, if it's not empty
						if (switchBuffers) activeBuffer = (activeBuffer == 0 ? 1 : 0); 
						
						totalLines++;
					}
				}
			} catch (Exception ex) {
		    	System.out.println("Error in reading the observation file: " + fileName);
		    	System.out.println("  The file does not follow an observation file (-o2) format.");
				System.exit(1);
			} finally {
				reader1.close();
				reader2.close();
			}
		} catch (FileNotFoundException ex) {
		     System.out.println("File not found: Failed to read two discrete observation files.");
		     System.exit(1);
		} catch (Exception ex) {
	    	System.out.println("Error in reading the observation file: " + fileName + " or " + fileName2);
	    	System.out.println("  These files might not follow observation files (-o2) format.");
			//ex.printStackTrace();
			System.exit(1);
		}
	}


	/**
	 * Reads two continuous observation files.
	 */
	public void read2ContinuousObservationsFiles() {
		cdata = new ContinuousData(fileName, fileName2);
		try {
			double[] Data1 = cdata.loadData(fileName);
			double[] Data2 = cdata.loadData(fileName2);
			cdata.DataList.add(Data1);
			cdata.DataList.add(Data2);
			//cdata.testSize = Math.min(Data1.length, Data2.length) / 2;
			
			// Fix data only for the work on the passport analyses
			// TODO: removed this because I don't think it's used any more.
			if(TestInfoLeak.fixMeanForPassportAnalyses) {
				cdata.fixedMeans(Data1, Data2);
				System.out.println("Fixing the mean of the data of passport analyses...");
			} else if(TestInfoLeak.fixMedianForPassportAnalyses) {
				cdata.fixedMedians(Data1, Data2);
				System.out.println("Fixing the median of the data of passport analyses...");
			}
		} catch(FileNotFoundException e) {
			System.out.println("File not found error:" + e);
			System.exit(1);
		} catch(Exception e) {
			System.out.println("Error in reading and parsing data");
			System.out.println("The data might not be continuous.");
			System.exit(1);
		}

	}


	/**
	 * Returns continuous data.
	 * 
	 * @return continuous data
	 */
	public ContinuousData getContinuousData() {
		return this.cdata;
	}
	
	
	/**
	 * Reads a discrete (prior) distribution file.
	 */
	public void readDistribution() {
		try {
			BufferedReader input =  new BufferedReader(new FileReader(fileName));
			try {
				Pattern pattern = Pattern.compile("^[\\s]*\\([\\s]*([\\.\\-\\w:]+)[\\s]*,[\\s]*([\\(|\\.|\\w|\\W|\\s|,|\\)]+)[\\s]*\\)");
				Matcher matcher;
				int lineNumber = 0;
				ArrayList<String> sts = new ArrayList<String>();
				ArrayList<Double> pmf = new ArrayList<Double>();

				String line;
				while ((line = input.readLine()) != null) {
					if((line.trim()).equalsIgnoreCase("") || (line.trim()).startsWith("//")) {
						continue;
					}
					//System.out.println(line + " : " + lineNumber);
					matcher = pattern.matcher(line.trim());
					if (!matcher.find()) System.out.println("Syntax error while reading line: " + line);

					double prob = 0;
					try {
						//System.out.println("Prob : " + matcher.group(1) + "   Name : " + matcher.group(2));
						prob = Double.parseDouble(matcher.group(1));
					} catch(Exception e) {
						System.out.println("Error in reading the input (prior) file.");
				    	System.out.println("  The file does not follow the prior file (-prior) format.");
						System.exit(1);
					}
					
					sts.add(matcher.group(2));
					pmf.add(prob);
					lineNumber++;
				}
				//System.out.println("lineNumber : " + lineNumber);
				pd = new ProbDist(lineNumber);
				for(int i = 0; i < lineNumber; i++) {
					State st = new State();
					//System.out.println("i : " + i);
					//System.out.println("Stat : " + sts.get(i));
					st.updateValue("input", sts.get(i));
					//System.out.println("Prob : " + pmf.get(i));
					pd.updateProb(st, pmf.get(i));
				}

			} catch(Exception ex) {
				if (verbose >= 5)
					ex.printStackTrace();
		    	System.out.println("Error in reading the prior file: " + fileName);
		    	System.out.println("  The file does not follow the prior file (-prior) format.");
				System.exit(1);
			}
			finally {
				input.close();
			}
	    } catch(FileNotFoundException ex) {
		     System.out.println("Prior file not found:" + fileName);
		     System.out.println("Failed to read a discrete prior file.");
		     System.exit(1);
		} catch(Exception ex) {
	    	System.out.println("Error in reading the prior file: " + fileName);
	    	System.out.println("  The file might not follow the prior file (-prior) format.");
			//ex.printStackTrace();
			System.exit(1);
	   }
	}

	
	/**
	 * Reads a discrete guess domain file.
	 */
	public void readGuessDomain() {
		try {
			guessDomain = new TreeSet<String>();
			BufferedReader input =  new BufferedReader(new FileReader(fileName));
			try {
				Pattern pattern = Pattern.compile("\\{[\\s]*(.*)[\\s]*\\}");
				Matcher matcher;

				String line;
				while ((line = input.readLine()) != null) {
					if((line.trim()).equalsIgnoreCase("") || (line.trim()).startsWith("//")) {
						continue;
					}
					matcher = pattern.matcher(line.trim());
					if (!matcher.find()) {
						System.out.println("Syntax error while reading line: " + line);
					} else {
						//System.out.println("matcher.group(1): " + matcher.group(1));
						guessDomain.add(matcher.group(1));
					}
				}
				if (verbose >= 5) {
					// Print the set of all guesses
					System.out.println("Guess domain = {");
					for(String str : guessDomain) {
						System.out.println("  {" + str +"},");
					}
					System.out.println("}");
				}
			} catch(Exception ex) {
				if (verbose >= 5)
					ex.printStackTrace();
		    	System.out.println("Error in reading the guess domain file: " + fileName);
		    	System.out.println("  The file does not follow a guess domain file (-guess) format.");
				System.exit(1);
			}
			finally {
				input.close();
			}
	    } catch(FileNotFoundException ex) {
		     System.out.println("Guess domain file not found:" + fileName);
		     System.out.println("Failed to read a guess domain file.");
		     System.exit(1);
		} catch(Exception ex) {
	    	System.out.println("Error in reading the guess domain file: " + fileName);
	    	System.out.println("  The file might not follow a guess domain file (-guess) format.");
			//ex.printStackTrace();
			System.exit(1);
	   }
	}
	
}
