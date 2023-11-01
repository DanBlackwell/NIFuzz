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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import bham.leakiest.comparator.*;

/**
 * This class represents an information theoretic channel.
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.4.4
 */
public class Channel {
	/*
	 * outputNames is an array of the output action labels.
	 * outputNames[i] is the entry in the 1st row and ith column of the matrix.
	 */
	String[] outputNames; 

	// Array list used for sorting outputNames
	//private ArrayList<StringWithSortIndex> outputNamesSorted = new ArrayList<StringWithSortIndex>();
	private ArrayList<Pair<String,Integer>> outputNamesSorted = new ArrayList<Pair<String,Integer>>();

	/*
	 * an array of the input action labels. For single user matrixes
	 * inputNames[i] will be the output of the ith row of the matrix.
	 * for multi-access channels the row label is found via inputsPerRow
	 */
	String[] inputNames;

	// The channel matrix
	double[][] channelMatrix_W; 
	double[][] channelMatrix_W_Sorted; 

	// inputsPerRow is an array of Vectors where inputPerRow[i] is a Vector
	// of the indexes of the inputs on row i of the channel matrix 
	Vector[] inputsPerRow;

	// In Condition channels groupNames[i] is the group of the ith row
	String[] groupNames;

	// currently unused
	// This will be used later when I add multipule groups for a row
	Vector[] groupsPerRow;

	// for row i: groupNames[groupForRow[i]] is its group label.
	int[] groupForRow;

	// rowsForGroup[i] is a Vector of the rows that are in group groupNames[i]
	Vector[] rowsForGroup;

	// Is the channel single user, multi-access etc.
	int kind;
	private boolean sortOutputsDouble = true;
	private boolean sortOutputsDoubleDone = false;

	// Variables from TestInfoLeak
	private static boolean readFromChanFile = TestInfoLeak.readFromChanFile;
	private static int verbose = TestInfoLeak.verbose;
	
	/*
	 * Represents (basic) channels. (Only this kind of channels is supproted.)
	 */
	static final int BASIC = 1;
	
	/*
	 * Represents multi-access channels. (Not supproted.)
	 */
	static final int MULTI = 2;
	
	/*
	 * Represetns conditional channels. (Not supproted.)
	 */
	static final int COND = 3;


	/**
	 * Constructs the empty channel.
	 */
	public Channel() {}


	/**
	 * Constructs a channel with initial values.
	 * 
	 * @param kind kind of channels.
	 * @param inputNames input names
	 * @param outputNames output names
	 * @param matrix channel matrix
	 */
	public Channel(int kind, String[] inputNames, String[] outputNames, double[][] matrix) {
		this.kind = kind;
		this.inputNames = inputNames;
		this.outputNames = outputNames;
		this.channelMatrix_W = matrix;
	}

	/**
	 * Constructs a (basic) channel with initial values.
	 * 
	 * @param inputNames input names
	 * @param outputNames output names
	 * @param matrix channel matrix
	 */
	public Channel(String[] inputNames, String[] outputNames, double[][] matrix) {
		this.kind = BASIC;
		this.inputNames = inputNames;
		this.outputNames = outputNames;
		this.channelMatrix_W = matrix;
	}

	public String[]   getOutputNames()   { return outputNames; }
	public String[]   getInputNames()    { return inputNames; } 
//	public String[]   getGroupNames()    { return groupNames; }
	
	/**
	 * Returns the channel matrix.
	 * 
	 * @return channel matrix
	 */
	public double[][] getMatrix()        { return channelMatrix_W; } 

//	public Vector[]   getInputsPerRow()  { return inputsPerRow; }
//	public Vector     getInputRow(int i) { return inputsPerRow[i]; }
//	public Vector[]   getGroupsPerRow()  { return groupsPerRow; }
//	public Vector[]   getRowsForGroup()  { return rowsForGroup; }
//	public int        getKind()          { return kind; }


	/**
	 * Returns the number of inputs.
	 * 
	 * @return the number of inputs
	 */
	public int        noOfInputs()        { return inputNames.length; }

	
	/**
	 * Returns the number of outputs.
	 * 
	 * @return the number of outputs
	 */
	public int        noOfOutputs()       { return outputNames.length; }

//	public int        noOfRows()          { return channelMatrix_W.length; }
//	public double     prob(int a,int o)   { return channelMatrix_W[a][o]; }

//	public String getInputName(int i)  { return inputNames[i]; }
//	public String getOutputName(int i) { return outputNames[i]; }

	
	/**
	 * Sets the array of output names.
	 * @param arg array of output names
	 */
	public void setOutputNames(String[] arg)  { outputNames = arg; }
	
	/**
	 * Sets the array of input names.
	 * @param arg array of input names
	 */
	public void setInputNames(String[] arg)   { inputNames = arg; }

	/**
	 * Sets the array of group names.
	 * @param arg array of group names
	 */
	public void setGroupNames(String[] arg)   { groupNames = arg; }

	/**
	 * Sets the channel matrix.
	 * @param arg channel matrix
	 */
	public void setMatrix(double[][] arg)     { channelMatrix_W = arg; } 

	/**
	 * Sets inputsPerRow.
	 * @param arg vector of inputsPerRow's.
	 */
	public void setInputsPerRow(Vector[] arg) { inputsPerRow = arg; }
//	public void setGroupsPerRow(Vector[] arg) { groupsPerRow = arg; }

	/**
	 * Sets groupForRow.
	 * @param arg vector of groupForRow's.
	 */
	public void setGroupForRow(int[]arg)      { groupForRow = arg; }
//	public void setKind(int arg)              { kind = arg; }

	/**
	 * Sets rowsForGroup.
	 * @param arg vector of rowsForGroup's.
	 */
	public void setRowsForGroup(Vector[] arg) { rowsForGroup = arg; }


	/*
	 * Returns the label for the row.
	 * 
	 * @param rowNo number of inputNames 
	 * @return row label
	 */
	private String getRowLabel(int rowNo) {
		switch(kind) {
			case BASIC: return (inputNames[rowNo]);
			case COND: return (inputNames[rowNo]+":"+groupNames[groupForRow[rowNo]]);
		}
		if(kind == BASIC || kind == COND) {
			return (inputNames[rowNo]);
		} else {
			String result ="";
			if( inputsPerRow[rowNo].size() >0 ) {
				result = inputNames[((Integer)inputsPerRow[rowNo].get(0)).intValue()];
				for(int i = 1; i < inputsPerRow[rowNo].size(); i++) {
					result = result +", "+inputNames[((Integer)inputsPerRow[rowNo].get(i)).intValue()];
				}	
			}
			return result;
		}	
	}

	////////////////////////////
	// Properties on the channel
	/**
	 * Checks whether this channel is well-formed or not.
	 * 
	 * @param accuracy possible error of the summation of each row
	 * @return whether this channel is well-formed or not
	 */
	public boolean isWellFormed(double accuracy) {
		// Check whether the number of input labels matches with the size of the matrix
		if(inputNames.length != channelMatrix_W.length) {
	    	System.out.println("Caution: inputNames.length = " + inputNames.length + " channelMatrix_W.length = " + channelMatrix_W.length);
			return false;
		}
		// Check whether the number of output labels matches with the size of the matrix
		if(outputNames.length != channelMatrix_W[0].length) {
	    	System.out.println("Caution: outputNames.length = " + outputNames.length + " channelMatrix_W[0].length = " + channelMatrix_W[0].length);
			return false;
		}
		// Check whether the summation of each row is 1 or almost 1
		for(int row = 0; row < inputNames.length; row++) {
			double sum = 0.0;
			for(int col = 0; col < outputNames.length; col++) {
				sum += channelMatrix_W[row][col];
			}
			if(sum < 1.0 - accuracy || sum > 1.0 + accuracy) {
		    	System.out.println("Caution: The summation of the row " + row + " = " + sum);
				return false;
			}
		}
		return true;
	}

	////////////////////////////////////////////
	// Joint distribution on inputs and outputs
	/**
	 * Return the joint distribution on inputs and outputs
	 * generated by a given prior and this channel.
	 * 
	 * @param prior prior distribution
	 * @return the joint distribution generated by prior and channel
	 */
	public Channel getJointDist(ProbDist prior) {
		double[] pmf = prior.probDistToPMFArray(this.getInputNames());
		double[][] chMatrix = this.getMatrix();
		int numRows = this.noOfInputs();
		int numCols = this.noOfOutputs();
		double[][] jointMatrix = new double[numRows][numCols];
		for(int row = 0; row < numRows; row++) {
			for(int col = 0; col < numCols; col++) {
				jointMatrix[row][col] = pmf[row] * chMatrix[row][col];
			}
		}
		Channel jointCh = new Channel(this.getInputNames(), this.getOutputNames(), jointMatrix);
		return jointCh;
	}
	
	/**
	 * Return the joint distribution on inputs and outputs generated by prior and channel.
	 * 
	 * @param prior prior distribution
	 * @param channel channel
	 * @return the joint distribution generated by prior and channel
	 */
	public static Channel getJointDist(ProbDist prior, Channel channel) {
		double[] pmf = prior.probDistToPMFArray(channel.getInputNames());
		double[][] chMatrix = channel.getMatrix();
		int numRows = channel.noOfInputs();
		int numCols = channel.noOfOutputs();
		double[][] jointMatrix = new double[numRows][numCols];
		for(int row = 0; row < numRows; row++) {
			for(int col = 0; col < numCols; col++) {
				jointMatrix[row][col] = pmf[row] * chMatrix[row][col];
			}
		}
		Channel jointCh = new Channel(channel.getInputNames(), channel.getOutputNames(), jointMatrix);
		return jointCh;
	}

	////////////////////////////
	// Posterior distribution
	public ProbDist getPosteriorProbDist(ProbDist prior) {
		// Channel
		String[] inputNames = this.getInputNames();
		String[] outputNames = this.getOutputNames();
		double[][] matrix = this.getMatrix();
		// Prior
		double[] priorPMF = prior.probDistToPMFArray(inputNames);
		
		// Check the inner dimension
		if(priorPMF.length != matrix.length) {
	    	System.out.println("  The number of prior          = " + priorPMF.length);
	    	System.out.println("  The number of rows of matrix = " + matrix.length);
			System.exit(1);
		}

		// Size of prior and posterior
		int numRows = priorPMF.length;
		int numCols = matrix[0].length;
		
		// Calculate the posterior distribution
		double[] postPMF = new double[numCols];
		for(int col = 0; col < numCols; col++) {
			postPMF[col] = 0.0;
			for(int row = 0; row < numRows; row++) {
				postPMF[col] += priorPMF[row] * matrix[row][col];
			}
		}

		// Construct the output probability distribution
		ProbDist post = new ProbDist(outputNames, postPMF);
		return post;
	}
	
	
	////////////////////////////
	// Composition Functions
	/**
	 * Calculate the channel composed in parallel.
	 * 
	 * @param channels array of channels
	 * @return the channel composed in parallel
	 */
	public static Channel parallelComposition(Channel[] channels) {
		return parallelComposition(channels, false, false);
	}
	
	/**
	 * Calculate the channel composed in parallel.
	 * 
	 * @param channels array of channels
	 * @removeBrackets1 whether removing the outermost rackets from composed inputs
	 * @removeBrackets2 whether removing the outermost rackets from composed outputs
	 * @return the channel composed in parallel
	 */
	public static Channel parallelComposition(Channel[] channels, boolean removeBrackets1, boolean removeBrackets2) {
		if(channels == null || channels.length <= 1) {
	    	System.out.println("Error in the channels.");
	    	System.out.println("  Incorrect channels are specified.");
			System.exit(1);
		}
		int numChannels = channels.length;

		// Calculate the size of the composed channel
		int numRows = 1;
		int numCols = 1;
		for(int num = 0; num < numChannels; num++) {
			numRows *= channels[num].noOfInputs();
			numCols *= channels[num].noOfOutputs();
		}

		// Initialize tmpMatrix
		int tmpMatrixNumRows = numRows/channels[numChannels-1].noOfInputs();
		int tmpMatrixNumCols = numCols/channels[numChannels-1].noOfOutputs();
		double[][] tmpMatrix = new double[tmpMatrixNumRows][tmpMatrixNumCols];
		for(int i = 0; i < channels[0].noOfInputs(); i++) {
			for(int j = 0; j < channels[0].noOfOutputs(); j++) {
				tmpMatrix[i][j] = channels[0].getMatrix()[i][j];
			}
		}
		
		// Calculate the matrix of the composed channel
		double[][] matrix = new double[numRows][numCols];
		int tmpNumRows = channels[0].noOfInputs();
		int tmpNumCols = channels[0].noOfOutputs();
		for(int num = 0; num < numChannels-1; num++) {
			double[][] matrix2 = channels[num+1].getMatrix();
			/*
	    	System.out.println("----------");
	    	System.out.println("  num = " + num);
	    	System.out.println("  tmpNumRows = " + tmpNumRows);
	    	System.out.println("  tmpNumCols = " + tmpNumCols);
	    	System.out.println("  matrix2.length = " + matrix2.length);
	    	System.out.println("  matrix2[0].length = " + matrix2[0].length);
	    	*/
			matrix = parallelComposition(tmpMatrix, matrix2, tmpNumRows, tmpNumCols, matrix2.length, matrix2[0].length);

			/*
	    	System.out.print("  tmpNumRows = " + tmpNumRows);
	    	System.out.println("  tmpNumCols = " + tmpNumCols);
	    	System.out.print("  matrix2.length = " + matrix2.length);
	    	System.out.println("  matrix2[0].length = " + matrix2[0].length);
	    	*/
	    	// copy matrix to tmpMatrix
	    	if(num < numChannels - 2) {
	    		for(int i = 0; i < tmpNumRows * matrix2.length; i++) {
	    			for(int j = 0; j < tmpNumCols * matrix2[0].length; j++) {
	    				//System.out.println("  i,j = " + i + ", " + j + "->" + matrix[i][j]);
	    				tmpMatrix[i][j] = matrix[i][j];
	    			}
	    		}
	    	}
			tmpNumRows *= channels[num].noOfInputs();
			tmpNumCols *= channels[num].noOfOutputs();
		}

		// Calculate the input names of the composed channel
		if(verbose >= 5) {
			System.out.println("--------------------");
		}
		String[] composedInputNames = new String[numRows];
		for(int i = 0; i < channels[0].noOfInputs(); i++) {
			composedInputNames[i] = channels[0].getInputNames()[i];
		}
		tmpNumRows = 1;
		for(int num = 0; num < numChannels-1; num++) {
			tmpNumRows *= channels[num].noOfInputs();
	    	//System.out.println("  channels[num+0].noOfInputs() = " + channels[num].noOfInputs());
	    	//System.out.println("  tmpNumRows = " + tmpNumRows);
	    	//System.out.println("  channels[num+1].noOfInputs() = " + channels[num+1].noOfInputs());
	    	//System.out.println("  numRows   = " + numRows);
			composedInputNames = parallelComposition(composedInputNames, channels[num+1].getInputNames(), tmpNumRows, channels[num+1].noOfInputs(), numRows, removeBrackets1, "");
		}
		for(int i = 0; i < composedInputNames.length; i++) {
			composedInputNames[i] = "(" + composedInputNames[i] + ")";
		}

		// Calculate the output names of the composed channel
		String[] composedOutputNames = new String[numRows];
		for(int j = 0; j < channels[0].noOfOutputs(); j++) {
			composedOutputNames[j] = channels[0].getOutputNames()[j];
		}
		tmpNumCols = 1;
		for(int num = 0; num < numChannels-1; num++) {
			tmpNumCols *= channels[num].noOfOutputs();
			composedOutputNames = parallelComposition(composedOutputNames, channels[num+1].getOutputNames(), tmpNumCols, channels[num+1].noOfOutputs(), numCols, removeBrackets2, "");
		}
		for(int i = 0; i < composedOutputNames.length; i++) {
			composedOutputNames[i] = "(" + composedOutputNames[i] + ")";
		}

		Channel ch = new Channel(BASIC, composedInputNames, composedOutputNames, matrix);
		return ch;
	}

	/*
	 * Returns the matrix C of parallel composition of two matrices A, B
	 * where C[j_max i + j, l_max k + l] = A[i,k] B[j,l].
	 * 
	 * @param matrix1 channel matrix 1
	 * @param matrix2 channel matrix 2
	 * @return the parallel composition of matrices 1 and 2
	 */
	private static double[][] parallelComposition(double[][] matrix1, double[][] matrix2, int matrix1noOfInputs, int matrix1noOfOutputs, int matrix2noOfInputs, int matrix2noOfOutputs) {
		// Check the size of the given two matrices
		if(matrix1noOfInputs > matrix1.length || matrix1noOfOutputs > matrix1[0].length ||
		   matrix2noOfInputs > matrix2.length || matrix2noOfOutputs > matrix2[0].length ) {
	    	System.out.println("Error in the sizes of matrices.");
	    	System.out.println("  The actual size of matrix1 =    (" + matrix1[0].length + ", " + matrix1.length + ")");
	    	System.out.println("  The actual size of matrix2 =    (" + matrix2[0].length + ", " + matrix2.length + ")");
	    	System.out.println("  The specified size of matrix1 = (" + matrix1noOfInputs + ", " + matrix1noOfOutputs + ")");
	    	System.out.println("  The specified size of matrix2 = (" + matrix2noOfInputs + ", " + matrix2noOfOutputs + ")");
			System.exit(1);
		}
		
		// Calculate the size of the composed channel
		int numRows = matrix1noOfInputs * matrix2noOfInputs;
		int numCols = matrix1noOfOutputs * matrix2noOfOutputs;
    	//System.out.println("  numRows = " + numRows);
    	//System.out.println("  numCols = " + numCols);

		// Calculate the composed channel
		double[][] matrix = new double[numRows][numCols];
    	//System.out.println("  iMax = " + matrix1noOfInputs + " - " + matrix1.length);
    	//System.out.println("  jMax = " + matrix1noOfOutputs + " - " + matrix1[0].length);
    	//System.out.println("  kMax = " + matrix2noOfInputs + " - " + matrix2.length);
    	//System.out.println("  lMax = " + matrix2noOfOutputs + " - " + matrix2[0].length);
		for(int i = 0; i < matrix1noOfInputs; i++) {
			for(int j = 0; j < matrix2noOfInputs; j++) {
				int row = matrix2noOfInputs * i + j;
				for(int k = 0; k < matrix1noOfOutputs; k++) {
					double a = matrix1[i][k];
					int lMaxk = matrix2noOfOutputs * k;
					for(int l = 0; l < matrix2noOfOutputs; l++) {
						int col = lMaxk + l;
						/*
				    	System.out.print("  i,j,k,l = " + i + " "+ j + " " + k + " " + l + "  row = " + row + "  col = " + col);
				    	System.out.print("  matrix1[" + i + "][" + k + "] = ");
				    	System.out.printf("%6.4f", a);
				    	System.out.print("  matrix2[" + j + "][" + l + "] = ");
				    	System.out.print(matrix2[j][l]);
				    	*/
						matrix[row][col] = matrix2[j][l] * a;
				    	//System.out.print("  matrix[" + row + "][" + col + "] = ");
				    	//System.out.printf("%6.4f", matrix[row][col]);
				    	//System.out.println("");
					}
				}
			}
		}
		return matrix;
	}

	/*
	 * Returns the input/output names of the channel composed of two channels in parallel.
	 * 
	 * @param names1 input/output names of a channel
	 * @param names2 input/output names of a channel
	 * @param size1 the size of array names1
	 * @param size2 the size of array names2
	 * @param size the size of the returned array
	 * @return input/output names of the channel composed in parallel
	 */
	public static String[] parallelComposition(String[] names1, String[] names2, int size1, int size2, int size) {
		return parallelComposition(names1, names2, size1, size2, size, false, "");
	}
	
	/*
	 * Returns the input/output names of the channel composed of two channels in parallel.
	 * 
	 * @param names1 input/output names of a channel
	 * @param names2 input/output names of a channel
	 * @param size1 the size of array names1
	 * @param size2 the size of array names2
	 * @param size the size of the returned array
	 * @param removeBrackets whether removing the outermost brackets
	 * @param separator string added as a separator between two outputs from distinct channels
	 * @return input/output names of the channel composed in parallel
	 */
	public static String[] parallelComposition(String[] names1, String[] names2, int size1, int size2, int size, boolean removeBrackets, String separator) {
		// Check the size of the given two arrays
		if(size1 > names1.length || size2 > names2.length) {
	    	System.out.println("Error in the sizes of matrices.");
	    	System.out.println("  The actual size of names1 =    " + names1.length);
	    	System.out.println("  The actual size of names2 =    " + names2.length);
	    	System.out.println("  The specified size of names1 = " + size1);
	    	System.out.println("  The specified size of names2 = " + size2);
			System.exit(1);
		}
		// Calculate the array of input/output names for the composed channel
		String[] names = new String[size];
		for(int i = 0; i < size1; i++) {
			for(int j = 0; j < size2; j++) {
		    	//System.out.print("i,j = " + i + ", " + j + "  names[" + (names2.length * i + j) + "] =  ");
	    		String name1 = names1[i];
	    		String name2 = names2[j];
	    		
		    	if(removeBrackets) {
	    			// Remove the outermost brackets
		    		try {
		    			Pattern pattern = Pattern.compile("\\([\\s]*([\\W\\w]+)[\\s]*\\)");
		    			Matcher matcher = pattern.matcher(name1);
		    			if (matcher.find()) {
		    				name1 = matcher.group(1);
		    			}
		    		} catch(Exception ex) {
		    			System.out.println("Caution: Couldnot remove brackets from " + name1);
		    		}
		    		try {
		    			Pattern pattern = Pattern.compile("\\([\\s]*([\\W\\w]+)[\\s]*\\)");
		    			Matcher matcher = pattern.matcher(name2);
		    			if (matcher.find()) {
		    				name2 = matcher.group(1);
		    			}
		    		} catch(Exception ex) {
		    			System.out.println("Caution: Couldnot remove brackets from " + name2);
		    		}
		    	}
		    	if(separator != "") {
					names[names2.length * i + j] = name1 + ", " + separator + ", " + name2;
		    	} else {
					names[names2.length * i + j] = name1 + ", " + name2;
		    	}
		    	//System.out.print(names[names2.length * i + j] + ";");
		    	//System.out.println("  size = (" + size1 + ", " + size2 + ") -> " + size);
			}
		}
		return names;
	}

	
	
	
	// TODO: this is completely wrong.
	private static Channel disjointMerge(Channel[] channels) {
		if(channels == null || channels.length <= 1) {
	    	System.out.println("Error in the channels.");
	    	System.out.println("  Incorrect channels are specified.");
			System.exit(1);
		}
		int numChannels = channels.length;
		
		// Calculate the size of the composed channel
		int numRows = 0;
		int numCols = 0;
		for(int num = 0; num < numChannels; num++) {
			numRows += channels[num].noOfInputs();
			numCols += channels[num].noOfOutputs();
		}
		
		// Calculate the composed channel
		double[][] matrix = new double[numRows][numCols];
		int currentRow = 0;
		int currentCol = 0;
		for(int num = 0; num < numChannels; num++) {
			double[][] currentMatrix = channels[num].getMatrix();
			for(int i = 0; i < channels[num].noOfInputs(); i++) {
				for(int j = 0; j < channels[num].noOfOutputs(); j++) {
					matrix[currentRow + i][currentCol + j] = currentMatrix[i][j];
				}
			}
			currentRow += channels[num].noOfInputs();
			currentCol += channels[num].noOfOutputs();
		}
		
		// Calculate the array of input names for the composed channel
		String[] inputNames = new String[numRows];
    	//System.out.println("  numRows = " + numRows);
		currentRow = 0;
		for(int num = 0; num < numChannels; num++) {
			for(int i = 0; i < channels[num].noOfInputs(); i++) {
				inputNames[currentRow + i] = "__" + num + "_" + channels[num].getInputNames()[i];
		    	//System.out.println("  in[" + (currentRow + i) + "] =  " + inputNames[currentRow + i]);
			}
			currentRow += channels[num].noOfInputs();
		}

		// Calculate the array of output names for the composed channel
		String[] outputNames = new String[numCols];
    	System.out.println("  numCols = " + numCols);
		currentCol = 0;
		for(int num = 0; num < numChannels; num++) {
			for(int j = 0; j < channels[num].noOfOutputs(); j++) {
				outputNames[currentCol + j] = "__" + num + "_" + channels[num].getOutputNames()[j];
		    	//System.out.println("  out[" + (currentCol + j) + "] = " + outputNames[currentCol + j]);
			}
			currentCol += channels[num].noOfOutputs();
		}
		Channel ch = new Channel(BASIC, inputNames, outputNames, matrix);
		return ch;
	}
	
	/**
	 * Returns the cascade channel (sequential composition) of given channels.
	 * 
	 * @param channels array of channels
	 * @return the cascade channel of channels
	 */
	public static Channel cascade(Channel[] channels) {
		if(channels == null || channels.length <= 1) {
	    	System.out.println("Error in the channels.");
	    	System.out.println("  Incorrect channels are specified.");
			System.exit(1);
		}
		int numChannels = channels.length;

		Channel ch = new Channel();
		for(int num = 0; num < numChannels-1; num++) {
			// M_i+1 := M_i multiplied by C_i+1
			ch = cascade(channels[num], channels[num+1]);
		}

		/*
		// M_0 := C_0  for initialization
		double[][] matrix = channels[0].getMatrix();
		for(int num = 0; num < numChannels-1; num++) {
			// M_i+1 := M_i multiplied by C_i+1
			matrix = cascade(matrix, channels[num+1].getMatrix());
		}
		
		String[] inputNames = channels[0].getInputNames();
		String[] outputNames = channels[numChannels-1].getOutputNames();
		Channel ch = new Channel(inputNames, outputNames, matrix);
		*/
		return ch;
	}

	/**
	 * Returns the cascade composition of two channels.
	 * 
	 * @param ch1 channel 1
	 * @param ch2 channel 2
	 * @return the cascade composition of ch1 and ch2
	 */
	private static Channel cascade(Channel ch1, Channel ch2) {
		// Channel1
		String[] inputNames1 = ch1.getInputNames();
		String[] outputNames1 = ch1.getOutputNames();
		double[][] matrix1 = ch1.getMatrix();
		// Channel2
		String[] inputNames2 = ch2.getInputNames();
		String[] outputNames2 = ch2.getOutputNames();
		double[][] matrix2 = ch2.getMatrix();
		
		// Check the inner dimension
		if(matrix1[0].length != matrix2.length) {
	    	System.out.println("  The number of columns of matrix1 = " + matrix1[0].length);
	    	System.out.println("  The number of rows of matrix2    = " + matrix2.length);
			System.exit(1);
		}

		// Size of matrices
		int numRows = matrix1.length;
		int numCols = matrix2[0].length;
		int numInner = matrix1[0].length;
		
		// Calculate the matrix of the cascade
		double[][] matrix = new double[numRows][numCols];
		for(int i = 0; i < numRows; i++) {
			for(int j = 0; j < numCols; j++) {
				matrix[i][j] = 0.0;
			}
			for(int k1 = 0; k1 < numInner; k1++) {
				int k2 = k1;
				String innerName = outputNames1[k1];
				for(int row2 = 0; row2 < numInner; row2++) {
					if(innerName.equals(inputNames2[row2])) {
						k2 = row2;
				    	//System.out.println("  k1 = " + k1 + "  k2 =  " + k2 + " innerName = " + innerName);
						break;
					}
				}
				if(k2 < 0) {
			    	System.out.println("Error: The output name of channel 1 was not found in channel 2: " + innerName);
					System.exit(1);
				}
				double d = matrix1[i][k1];
				for(int j = 0; j < numCols; j++) {
					matrix[i][j] += matrix2[k2][j] * d;
				}
			}
		}

		// Construct the cascade channel
		Channel ch = new Channel(inputNames1, outputNames2, matrix);
		return ch;
	}

	
	/*
	 * Returns the cascade composition of two channel matrices.
	 * 
	 * @param matrix1 channel matrix 1
	 * @param matrix2 channel matrix 2
	 * @return the cascade composition of matrices 1 and 2
	 */
	private static double[][] cascade(double[][] matrix1, double[][] matrix2) {
		// Check the inner dimension
		if(matrix1[0].length != matrix2.length) {
	    	System.out.println("  The number of columns of matrix1 = " + matrix1[0].length);
	    	System.out.println("  The number of rows of matrix2    = " + matrix2.length);
			System.exit(1);
		}
		
		int numRows = matrix1.length;
		int numCols = matrix2[0].length;
		int numInner = matrix1[0].length;
		double[][] matrix = new double[numRows][numCols];

		for(int i = 0; i < numRows; i++) {
			for(int j = 0; j < numCols; j++) {
				matrix[i][j] = 0.0;
			}
			for(int k = 0; k < numInner; k++) {
				double d = matrix1[i][k];
				for(int j = 0; j < numCols; j++) {
					matrix[i][j] += matrix2[k][j] * d;
				}
			}
		}
		return matrix;
	}

	
	////////////////////////////
	// Print functions
	//	
	/** 
	 * Prints i+1 spaces.
	 * 
	 * @param i the number of spaces printed
	 */
	public static void addspaces(int i)	{
		for(int j = 0; j <= i; j++)
			System.out.print(" ");
	}

	/*
	 * Prints the string and pads it to length i.
	 * @param s
	 * @param i
	 */
	protected static void printToLength(String s, int i) {
		System.out.print(s);
		for(int j = s.length(); j <= i; j++)
			System.out.print(" ");
	}

	/**
	 * Prints the channel to standard out.
	 */
	public void printChannel() {
		if(readFromChanFile) {
			System.out.println("The channel matrix to 4 decimal places:");
		} else {
			System.out.println("These observations lead to the following channel matrix, to 4 decimal places:");
		}
		// Do not sort if the number of columns is 1
		if(outputNames.length <= 1) {
			sortOutputsDouble = false;
		}

		// Sort the columns
		if(sortOutputsDouble && !sortOutputsDoubleDone) {
			sortByOutputValue();
			sortOutputsDoubleDone = true;
		}

		// Display the number of rows and columns of the channel matrix
		String sizeMatrix = "(" + inputNames.length + ", " + outputNames.length + ")";

		// Find maximum output length
		int maxOutLength = 0;
		for(int i = 0; i < outputNames.length ; i++) {
			maxOutLength = Math.max(maxOutLength, outputNames[i].length());
		}

		//Rounding probs to 4 d.p. therefore all probs have length 6 
		maxOutLength = Math.max(maxOutLength,6);

		// Find the Max Input row label length
		int maxInLength = 0;
		switch(kind) {
		case BASIC: 
			for(int i = 0; i < inputNames.length; i++) {
				maxInLength = Math.max(maxInLength,inputNames[i].length());
			}
			maxInLength = Math.max(maxInLength, sizeMatrix.length());
			break;
		/*
		case MULTI: 
			for(int i = 0; i < inputNames.length;i++) {
				maxInLength = maxInLength + inputNames[i].length();
			}
			maxInLength = maxInLength + inputNames.length;
			break;
		case COND: 
			for(int i = 0; i < inputNames.length; i++) {
				maxInLength = Math.max(maxInLength,inputNames[i].length());
			}
			int maxGroupLength = 0;
			for(int i = 0; i < groupNames.length; i++) {
				maxGroupLength = Math.max(maxGroupLength,groupNames[i].length());
			}
			maxInLength = maxInLength + maxGroupLength;
			break;
		*/
		}

		// Print the size of the matrix
		System.out.print(sizeMatrix);
		
		//Print the outputs names
		addspaces(maxInLength - sizeMatrix.length() + 2);
		for(int i = 0; i < outputNames.length; i++) {
			System.out.print("| ");
			if(sortOutputsDouble) {
				printToLength(outputNamesSorted.get(i).getElement1(), maxOutLength);
			}else {
				printToLength(outputNames[i], maxOutLength);
			}
		}
		System.out.println("");

		// Print each row
		for(int i = 0; i < channelMatrix_W.length; i++)	{
			printRow(i, maxInLength, maxOutLength);
		}
		System.out.println("");
	}

	/*
	 * Prints a row of this channel matrix.
	 */
	private void printRow(int RowNo, int maxInLength, int maxOutLength) {
		System.out.print(" ");
		printToLength(getRowLabel(RowNo), maxInLength+1); 
		for(int j = 0; j < outputNames.length; j++) { 
			System.out.print("| ");
			//int k = outputNamesSorted.get(j).getSortIndex();
			int k;
			if(sortOutputsDouble) {
				k = outputNamesSorted.get(j).getElement2();
			} else {
				k = j;
			}
			//System.out.print("(RowNo: " + RowNo + "  j: " + j + "  k: " + k + ") " + channelMatrix_W[RowNo][k] + " ");
			printToLength(Double.toString(Stats.round(channelMatrix_W[RowNo][k],Math.max(4,maxOutLength-2))),maxOutLength);  
		}
		System.out.println("");
	}

	/**
	 * Prints the joint probability distribution obtained by a given 
	 * (prior) input probability distribution and this channel to standard out.
	 * 
	 * @param pd (prior) input probability distribution
	 */
	public void printJointMatrix(ProbDist pd) {
		if(readFromChanFile) {
			System.out.println("The joint probability matrix to 4 decimal places:");
		} else {
			System.out.println("These observations lead to the following joint probability matrix, to 4 decimal places:");
		}
		// Sort the channel matrix by the output names
		if(sortOutputsDouble && !sortOutputsDoubleDone) {
			sortByOutputValue();
			sortOutputsDoubleDone = true;
		}
		
		// Display the number of rows and columns of the channel matrix
		String sizeMatrix = "(" + inputNames.length + ", " + outputNames.length + ")";

		// Find maximum output length
		int maxOutLength = 0;
		for(int i = 0; i < outputNames.length ; i++) {
			maxOutLength = Math.max(maxOutLength, outputNames[i].length());
		}
		//Rounding probs to 4 d.p. therefore all probs have length 6 
		maxOutLength = Math.max(maxOutLength,6);

		// Find the Max Input row label length
		int maxInLength = 0;
		switch(kind) {
		case BASIC: 
			for(int i = 0; i < inputNames.length; i++) {
				maxInLength = Math.max(maxInLength,inputNames[i].length());
			}
			maxInLength = Math.max(maxInLength, sizeMatrix.length());
			break;
		}

		// Print the size of the matrix
		System.out.print(sizeMatrix);
		
		//Print the outputs names
		addspaces(maxInLength - sizeMatrix.length() + 2);
		for(int i = 0; i < outputNames.length; i++) {
			System.out.print("| ");
			if(sortOutputsDouble) {
				//printToLength(outputNamesSorted.get(i).getOutputName(), maxOutLength);
				printToLength(outputNamesSorted.get(i).getElement1(), maxOutLength);
			}else {
				printToLength(outputNames[i], maxOutLength);
			}
		}
		System.out.println(""); 

		// Print each row of this channel matrix
		if(pd == null) {
			// Assume a uniform distribution if pd is null
			double inputProb = 1.0 / (double)channelMatrix_W.length;
			for(int i = 0; i < channelMatrix_W.length; i++)	{
				printRowJoint(i, maxInLength, maxOutLength, inputProb);
			}
		} else {
			for(int i = 0; i < channelMatrix_W.length; i++)	{
				double inputProb = pd.getProb(getRowLabel(i));
				printRowJoint(i, maxInLength, maxOutLength, inputProb);
			}
		}
		System.out.println("");
	}

	/*
	 * Prints a row of the joint probability matrix defined by this channel
	 * and a given (prior) input probability.
	 */
	private void printRowJoint(int RowNo, int maxInLength, int maxOutLength, double inputProb) {
		System.out.print(" ");
		printToLength(getRowLabel(RowNo), maxInLength+1); 
		for(int j = 0; j < outputNames.length; j++) { 
			System.out.print("| ");
			//int k = outputNamesSorted.get(j).getSortIndex();
			int k = outputNamesSorted.get(j).getElement2();
			//System.out.print("(j: " + j + "  k: " + k + ")");
			double prob = channelMatrix_W[RowNo][k] * inputProb;
			printToLength(Double.toString(Stats.round(prob,Math.max(4,maxOutLength-2))),maxOutLength);  
		}
		System.out.println("");
	}


	/*
	 * Produces index array that will be used to sort a channle matrix by outputNames.
	 */
	private void sortByOutputValue() {
		try {
			for(int i = 0; i < outputNames.length; i++) {
				//StringWithSortIndex swsi = new StringWithSortIndex();
				//swsi.setValues(outputNames[i], i);
				Pair<String,Integer> swsi = new Pair<String,Integer>(outputNames[i], i);
				outputNamesSorted.add(swsi);
			}
	        //ComparatorMulti comparator = new ComparatorMulti();
			ComparatorStringWithInt comparator = new ComparatorStringWithInt();
			Collections.sort(outputNamesSorted, comparator);
		} catch(Exception e) {
			System.out.println("Error: failed to sort outputs in sortByOutputValue(): " + e);
			System.exit(1);
		}
	}
	
}
