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

import java.util.Collection;
import java.io.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HashMap;
import java.util.regex.*;

/**
 * This class constructs a probability distribution and offers
 * methods for manipulating the probability distribution.
 * 
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.4.6
 */
public class ProbDist {
	private State[] sts;
	private double[] pmf;
	private int size;
	private int numJoint = 0;
	private HashMap<State, Double> dist;
	private ProbDist[] allMarginals; // all marginals of this distribution
	private boolean forbid_overwrite;
	private final int NOT_FOUND = -1;
	private final int NAN = -1;
    private static int verbose = TestInfoLeak.verbose;
	protected static final double ERROR = -1;
	protected static final double accuracy = 0.0000000001;
	
	/**
	 * Constructs the empty probability distribution.
	 * 
	 * @param numStates the number of states
	 */
	public ProbDist(int numStates) {
		size = numStates;
		forbid_overwrite = false; 
		sts = new State[numStates];
		pmf = new double[numStates];
		dist = new HashMap<State, Double>();
		
		if(verbose >= 5)
			System.out.println("A probability distribution is created.");
	}

	/*
 	 * Constructs a probability distribution with initial values
 	 * and lock.
 	 * 
	 * @param sts_in array of states
	 * @param pmf_in array of PMF
	 * @param lock forbids overwriting the probability distribution
	 * @param copy whether we copy arrays when creating a probability distribution
	 */
	private ProbDist(State[] sts_in, double[] pmf_in, boolean lock, boolean copy) {
		if(sts_in.length == pmf_in.length) {
			size = sts_in.length;
			forbid_overwrite = lock;
			sts = new State[size];
			pmf = new double[size];
			dist = new HashMap<State, Double>();
			if(copy) {
				System.arraycopy(sts_in, 0, sts, 0, sts_in.length);
				System.arraycopy(pmf_in, 0, pmf, 0, pmf_in.length);
				for(int i = 0; i < size; i++) {
					dist.put(sts_in[i], pmf_in[i]);
				}
			} else {
				sts = sts_in;
				pmf = pmf_in;
			}
			if(verbose >= 5)
				System.out.println("A probability distribution is created.");
		} else {
			System.out.println("Two arrays (input to ProbDist) have different lengths.");
		}
	}

	/**
 	 * Constructs a probability distribution with initial values.
	 * 
	 * @param sts_in array of states
	 * @param pmf_in array of PMF
	 */
	public ProbDist(State[] sts_in, double[] pmf_in) {
		this(sts_in, pmf_in, true, true);
	}

	/**
 	 * Constructs a probability distribution with initial values and lock.
	 * 
	 * @param sts_in array of states
	 * @param pmf_in array of PMF
	 * @param lock forbids overwriting the probability distribution
	 */
	public ProbDist(State[] sts_in, double[] pmf_in, boolean lock) {
		this(sts_in, pmf_in, lock, true);
	}

	/**
	 * Returns the probability distribution on a given array of states
	 * with a given probability mass function.
	 * 
	 * @param stateNames array of strings of state names
	 * @param pmf array of PMF
	 */
	public ProbDist(String[] stateNames, double[] pmf) {
		this(stateNames, pmf, true);
	}

	/**
	 * Returns the probability distribution on a given array of states
	 * with a given probability mass function.
	 * 
	 * @param stateNames array of strings of state names
	 * @param pmf array of PMF
	 * @param lock forbids overwriting the probability distribution
	 */
	public ProbDist(String[] stateNames, double[] pmf, boolean lock) {
		int numStates = stateNames.length;
		HashMap<State, Double> dist = new HashMap<State, Double>();
		for(int i = 0; i < numStates; i++) {
			State st = new State();
			st.updateValue("input", stateNames[i]);
			//System.out.println("  sts[" + i + "] = " + stateNames[i]);
			double prob = pmf[i];
			//System.out.println("  pmf[" + i + "] = " + prob);
			dist.put(st, prob);
		}
		this.dist = dist;
		this.sts = new State[dist.size()];
		this.pmf = new double[dist.size()];
		int i = 0;
		for(State st : this.dist.keySet()) {
			this.sts[i] = st;
			this.pmf[i] = dist.get(st);
			i++;
		}
	}

	/**
 	 * Constructs a probability distribution with initial values and lock.
	 * 
	 * @param dist_in a hash map that represents a probability distribution
	 * @param lock forbids overwriting the probability distribution
	 */
	public ProbDist(HashMap<State,Double> dist_in, boolean lock) {
		this.dist = dist_in;
		this.sts = new State[dist.size()];
		this.pmf = new double[dist.size()];
		int i = 0;
		for(State st : this.dist.keySet()) {
			this.sts[i] = st;
			this.pmf[i] = dist.get(st);
			i++;
		}
	}

	/**
	 * Returns the array of the uniform probabilities.
	 * 
	 * @param noOfInputs the size of uniform distribution
	 * @return the array of the uniform probabilities
	 */
	public static double[] uniformProbArray(int noOfInputs) {
		double[] pmf = new double[noOfInputs];
		for(int i = 0; i < pmf.length; i++) {
			pmf[i] = 1.0 / (double)noOfInputs;
		}
		return pmf;
	}
	
	/**
	 * Returns the uniform probability distribution on
	 * a given array of states.
	 * 
	 * @param stateNames array of strings of state names
	 * @param lock forbids overwriting the probability distribution
	 * @return the uniform probability distribution on stateNames
	 */
	public static ProbDist uniformProbDist(String[] stateNames, boolean lock) {
		int numStates = stateNames.length;
		HashMap<State, Double> dist = new HashMap<State, Double>();
		for(int i = 0; i < numStates; i++) {
			State st = new State();
			st.updateValue("input", stateNames[i]);
			//System.out.println("  sts[" + i + "] = " + stateNames[i]);
			double prob = 1.0 / (double)numStates;
			//System.out.println("  pmf[" + i + "] = " + prob);
			dist.put(st, prob);
		}
		ProbDist pd = new ProbDist(dist, lock);
		return pd;
	}
	
	/**
	 * Returns the array of the cumulative distribution of a given array of PMF.
	 * 
	 * @param  pmf array of PMF
	 * @return the array of the cumulative distribution of a given distribution
	 */
	public static double[] cumulativeProbArray(double[] pmf) {
		double[] cdf = new double[pmf.length];
		cdf[0] = pmf[0];
		for(int i = 1; i < pmf.length; i++) {
			cdf[i] = cdf[i-1] + pmf[i];
		}
		return cdf;
	}

	/**
	 * Returns the cumulative probability distribution of this distribution.
	 * 
	 * @param pd probability distribution
	 * @return the cumulative probability distribution of this distribution
	 */
	public ProbDist cumulativeProbDist() {
		State[] sts = this.getStatesArray();
		double[] cdf = cumulativeProbArray(this.getPMFArray());
		ProbDist cpd = new ProbDist(sts, cdf);
		return cpd;
	}

	/**
	 * Returns the joint distribution of a shared input.
	 * 
	 * @param numJoint the number of elements in a joint input
	 * @param lock forbids overwriting the probability distribution
	 * @return the joint distribution of a shared input
	 */
	public ProbDist sharedProbDist(int numJoint, boolean lock) {
		//System.out.println("  numJoint = " + numJoint);
		HashMap<State, Double> jdist = new HashMap<State, Double>();
		for(State st : this.dist.keySet()) {
			try {
				// string representing a joint state
				String str = st.getValue("input");
				String jstr = "(";
				for(int i = 0; i < numJoint; i++) {
					jstr += str;
					if(i != numJoint-1)
						jstr += ", ";
				}
				jstr += ")";
				
				// joint probability
				double jprob = this.dist.get(st);

				// add a joint distribution
				State jst = new State();
				//System.out.println("  sts = " + jstr);
				jst.updateValue("input", jstr);
				//System.out.println("  pmf = " + jprob);
				jdist.put(jst, jprob);
			} catch(Exception ex0) {
		    	System.out.println("Error in calculating the shared input distribution: " + ex0);
				System.exit(1);
			}
		}
		ProbDist pd = new ProbDist(jdist, lock);
		if(verbose >= 5) {
			pd.printProbDist();
		}
		return pd;
	}
	
	
	/*	
	private int getIndex(State st, boolean errormessage) {
		int i;
		//System.out.println(" sts.length: " + sts.length);
		for(i = 0; i < sts.length; i++) {
			//System.out.println(" i: " + i);
			if(sts[i] != null && sts[i].isEqual(st)) {
				return i;
			}
		}
		if(errormessage)
			System.out.println("Error in getIndex: \"" + st.stringState() + "\" is not found.");
		return NOT_FOUND;
	}
	*/

	/*
	 * Returns the probability of i-th element in the PMF array.
	 * 
	 * @param index index
	 * @return the probability for a given index in the PMF array
	 */
	/*
	public double getProb(int index) {
		double prob = 0;
		if(index >= 0 && index < size)
			prob = pmf[index];
		else
			System.out.println("Error in getProb: Failed to get the probability.");
		return prob;
	}
	*/

	/**
	 * Returns the probability of the state in the probability distribution.
	 * 
	 * @param str string that represents a state
	 * @return the probability of the state in the PMF array
	 */
	public double getProb(String str) {
		double result = 0;
		for(State st : this.dist.keySet()) {
			if(st.getValue("input").equals(str)) {
				result = this.dist.get(st);
				break;
			}
		}
		return result;
	}

	/**
	 * Returns the probability of the state in the probability distribution.
	 * 
	 * @param st state
	 * @return the probability of the state in the PMF array
	 */
	public double getProb(State st) {
		return this.dist.get(st);
	}

	/**
	 * Updates the probability distribution as to the probability of a state.
	 * @param st state
	 * @param prob probability
	 */
	public void updateProb(State st, double prob) {
		if(forbid_overwrite)
			System.out.println("Error in updateProb: Cannot overwrite the probability distribution.");
		else if(prob >= 0 && prob <= 1) {
			this.dist.put(st, prob);
			/*
			int index = getIndex(st, false); 
			if(index != NOT_FOUND) {
				pmf[index] = prob;
				//System.out.println(" index: " + index);
				if(verbose >= 5)
					System.out.println("Added Pr" + st.stringState() + " = " + prob);
			} else {
				boolean substitution = true;
				for(int i = 0; i < sts.length; i++)
					if(sts[i] == null) {
						sts[i] = st;
						pmf[i] = prob;
						substitution = false;
						//System.out.println(" i: " + i);
						break;
					}
				if(substitution)
					System.out.println("Error in updateProb: Probability distribution is full.");
				else if(verbose >= 5)
						System.out.println("Added Pr" + st.stringState() + " = " + prob);
			}
			*/
			if(verbose >= 7)
				System.out.println("Added Pr" + st.stringState() + " = " + prob);
		} else {
			System.out.println("Error in updateProb: " + prob + " is not a probability.");
		}
	}

    /**
	 * Removes a state from the probability distribution.
     * 
     * @param st state
     */
	public void removeProb(State st) {
		if(forbid_overwrite) {
			System.out.println("Error in updateProb: Cannot overwrite the probability distribution.");
			return;
		} else {
			this.dist.put(st, 0.0);
		}
		/*
		int index = getIndex(st, false);
		if(index != NOT_FOUND) {
			System.out.println("Removed Pr" + st.stringState() + " = " + pmf[index]);
			sts[index] = null;
			pmf[index] = NAN;
		} else {
			System.out.println("Error in removeProb: \"" + st.stringState() + "\" is not found.");
		}
		*/
	}

	/**
	 * Decides whether the probability distribution is well-defined or not.
	 * 
	 * @param error acceptable error rate for the calculation of probability distribution
	 * @return whether the probability distribution is well-defined or not
	 */
	public boolean isWellDefined(double error) {
		boolean wellDefined = true;

		/*
		// Check whether the array of states does not contain two identical states.
		for(int i = 0; i < sts.length; i++) {
			for(int j = i + 1; j < sts.length; j++) {
				//System.out.println("sts[" + i + "] = " + sts[i].stringState() + ".");
				//System.out.println("sts[" + j + "] = " + sts[j].stringState() + ".");
				if(sts[j] != null && sts[i].isEqual(sts[j])) {
					wellDefined = false;
					break;
				}
			}
		}
		*/
		
		// Check whether the summation of probabilities is almost 1.
		double sum = 0;
		for(Double prob : dist.values())
			sum += prob;
		if(sum > 1 + error || sum < 1 - error) {
			wellDefined = false;
			System.out.println("Sum of probabilities is " + sum + ".");
		}
		return wellDefined;
	}

	/**
	 * Print whether the probability distribution is well-defined or not.
	 * 
	 * @param error acceptable error rate for the calculation of probability distribution
	 */
	public void checkWellDefined(double error) {
		if(isWellDefined(error))
			System.out.println("The state is well-defined.");
		else
			System.out.println("Error: The state is not well-defined.");
	}
	
	/**
	 * Returns the size of the sample space.
	 * TODO:
	 * 
	 * @return the size of the sample space
	 */
	public int sizeSampleSpace() {
		return this.dist.size();
		//return size;
	}


	/**
	 * Returns the collection of the states of this probability distribution.
	 * 
	 * @return the collection of the states of this probability distribution
	 */
	public Collection<State> getStatesCollection() {
		return this.dist.keySet();
		//return this.sts;
	}

	/**
	 * Returns the array of the states of this probability distribution.
	 * 
	 * @return the array of the states of this probability distribution
	 */
	public State[] getStatesArray() {
		Collection<State> set = this.dist.keySet();
		this.sts = (State[]) set.toArray(new State[set.size()]);
		return this.sts;
	}

	/**
	 * Returns the collection of the probabilities of this probability distribution.
	 * 
	 * @return the collection of the probabilities of this probability distribution
	 */
	public Collection<Double> getPMFCollection() {
		return this.dist.values();
		//return this.pmf;
	}

	/**
	 * Returns the array of the probabilities of this probability distribution.
	 * 
	 * @return the array of the probabilities of this probability distribution
	 */
	public double[] getPMFArray() {
		Collection<Double> set = this.dist.values();
		double[] pmf = new double[set.size()];
		int i = 0;
		for(double d : set) {
			pmf[i] = d;
			i++;
		}
		return pmf;
		//return this.pmf;
	}

	/**
	 * Returns the array of the states in a given probability distribution
	 * that is sorted in the order of a given array inputNames.
	 * 
	 * @param inputNames array of the input action labels
	 * @return the array of the states in a probability distribution
	 */
	public State[] probDistToStatesArray(String[] inputNames) {
		if(inputNames.length != sts.length) {
			System.out.println("Error: The size of the (prior) input domain does not match the channel matrix.");
			System.out.println("  the input domain size: " + sts.length);
			System.out.println("  the number of rows in the channel matrix: " + inputNames.length);
			System.out.println("Failed to produce an array of states from the probability distribution.");
			System.exit(1);
		}
		State[] result = new State[inputNames.length];
		for(int i = 0; i < inputNames.length; i++) {
			//System.out.println("str: " + str);
			boolean found = false;
			for(State st : this.dist.keySet()) {
				//this.st.printState();
				if(inputNames[i].equals(st.getValue("input"))) {
					result[i] = st;
					found = true;
					break;
				}
			}
			if(!found) {
				System.out.println("Error: A label of the (prior) input domain is duplicated or missing in the channel matrix.");
				System.out.println("  Input domain: ");
				for(State st : this.dist.keySet()) {
					System.out.print("   ");
					st.printState();
				}
				System.out.println("  Labels of the channel matrix: ");
				System.out.print("    {");
				for(String s : inputNames) {
					System.out.print(" " + s);
				}
				System.out.println(" }");
				return null;
			}
		}
		return result;
	}
	
	/**
	 * Returns the array of a given probability distribution
	 * that is sorted in the order of a given array inputNames.
	 * 
	 * @param inputNames array of the input action labels
	 * @return the array of this probability distribution
	 */
	public double[] probDistToPMFArray(String[] inputNames) {
		if(inputNames.length < this.dist.size()) {
			System.out.println("Error: The size of the (prior) input domain is larger than the channel matrix.");
			System.out.println("  the input domain size: " + this.dist.size());
			System.out.println("  the number of rows in the channel matrix: " + inputNames.length);
			System.out.println("Failed to produce an array of probabilities from the probability distribution.");
			System.out.println("  See ProbDist.probDistToPMFArray(String[] inputNames) for debug.");
			System.exit(1);
		}
		double[] result = new double[inputNames.length];
		for(int i = 0; i < inputNames.length; i++) {
			//System.out.println("str: " + inputNames[i]);
			boolean found = false;
			for(State st : this.dist.keySet()) {
				//st.printState();
				//System.out.println("  st.getValue(input) = " + st.getValue("input"));
				if(inputNames[i].equals(st.getValue("input"))) {
					result[i] = this.dist.get(st);
					found = true;
					//System.out.println("  " + result[i] + "  i = " + i);
					break;
				}
			}
			//System.out.println("");
			if(!found) {
				result[i] = 0;
				//System.out.println("  " + result[i] + "  i = " + i);
			}
		}
		
		//Check the summation of all probabilities
		double sum1 = 0.0;
		double sum2 = 0.0;
		for(double d : result) {
			sum1 += d;
		}
		for(State st : this.dist.keySet()) {
			sum2 += this.dist.get(st);
		}
		if(Math.abs(sum1 - sum2) > accuracy) {
			System.out.println("Error: The states of the given prior and channel are different.");
			System.out.println("  Some label of the (prior) input domain is missing in the channel matrix.");
			System.out.println("  Input domain (size = " + (int)sum1 + "): ");
			for(State st : this.dist.keySet()) {
				System.out.print("   ");
				st.printState();
			}
			System.out.println("  Labels of the channel matrix (size = " + (int)sum2 + "): ");
			System.out.print("    {");
			for(int i = 0; i < inputNames.length; i++) {
				System.out.print(" " + inputNames[i]);
				if(i != inputNames.length - 1) {
					System.out.print(", ");
				}
			}
			System.out.println(" }");
			System.out.println("  See ProbDist.probDistToPMFArray(String[] inputNames) for debug.");
			System.exit(1);
		}
		return result;
	}

	/*
	 * Returns the set of the strings representing the sample spaces
	 * of all marginals of this probability dsitribution.
	 * 
	 * @return array of the strings representing the sample spaces
	 *         of all marginals of this probability dsitribution
	 */
	private ArrayList<HashSet<String>> getSampleSpace() {
		// Calculate all marginal distributions of jpd
		ProbDist[] marginals = this.getAllMarginals();
		int numJoint = marginals.length;
		
		// calculate the sample space
		ArrayList<HashSet<String>> sampleSpace = new ArrayList<HashSet<String>>();
		for(int i = 0; i < numJoint; i++) {
			Collection<State> sts = marginals[i].getStatesCollection();
			HashSet<String> hsst = new HashSet<String>();
			for(State st : sts) {
				hsst.add(st.getValue("input"));
			}
			sampleSpace.add(hsst);
		}
		return sampleSpace;
	}
	
	
	//////////////////////////////////////////////////////////////
	/**
	 * Returns the number of elements in a joint input.
	 * 
	 * @return the number of elements in a joint input
	 */
	public int getNumJoint() {
		//State[] sts = this.getStatesArray();
		if(this.numJoint > 1) {
			return this.numJoint;
		} else {
			try {
				for(State st : this.dist.keySet()) {
					String lineInput = st.getValue("input");
					//System.out.println("  lineInput = " + lineInput);
					String[] input = lineInput.split(",", 0);
					numJoint = input.length;
					//System.out.println("  numJoint  = " + numJoint);
					break;
				}
			} catch(Exception ex0) {
		    	System.out.println("Error in reading elements of an input." + ex0);
		    	System.out.println("  The file does not follow a prior file (-prior) format.");
				System.exit(1);
			}
		}
		return numJoint;
	}
	
	/**
	 * Check whether the number of channels matches with
	 * the size of the (prior) input distribution.
	 * 
	 * @param numChannels the number of channels
	 * @return whether the number of channels matches with
	 *         the size of the (prior) input distribution
	 */
	public boolean consistentChannelsAndPrior(int numChannels) {
		if(numChannels != this.getNumJoint()) {
	    	System.out.println("Error: The number of channels (" + (numChannels) +
	    						") does not match with the size of the (prior) input distribution (" +
	    						this.getNumJoint() + ").");
			System.exit(1);
		}
		return true;
	}

	
	private int stringToID(int num, String outcome, ArrayList<HashSet<String>> sampleSpace) {
		int index = 0;
		for(String str : sampleSpace.get(num)) {
			if(outcome.equals(str)) {
				break;
			} else {
				index++;
			}
		}
		return index;
	}

	private String IDToString(int num, int id, ArrayList<HashSet<String>> sampleSpace) {
		int index = 0;
		for(String str : sampleSpace.get(num)) {
			if(index == id) {
				return str;
			} else {
				index++;
			}
		}
		return "";
	}

	/**
	 * Check whether this probabiltiy distribution is jointly supported,
	 * i.e.,  p(x_1, ... , x_k) = 0 implies p(x_1) = ... = p(x_k) = 0.
	 * 
	 * @return whether this probabiltiy distribution is jointly supported
	 */
	public boolean isJointlySupported() {
		if(this.allMarginals == null) {
			this.getAllMarginals();
		}
		
		ArrayList<HashSet<String>> sampleSpace = this.getSampleSpace();
		int sizeSampleSpace = sampleSpace.size();
		int jointNum = this.getNumJoint();
		
		// sizes of sample spaces of marginal distributions
		int sizeSpace[] = new int[sizeSampleSpace];
		for(int i = 0; i < sizeSampleSpace; i++) {
			sizeSpace[i] = sampleSpace.get(i).size();
		}

		// bases (products of sizes of sample spaces of marginal distributions)
		int bases[] = new int[sizeSampleSpace+1];
		bases[0] = 1;
		for(int i = 1; i <= sizeSampleSpace; i++) {
			bases[i] = bases[i-1] * sizeSpace[i-1];
		}
		
		// make a table that maps the ID of a sample to its probability
		HashMap<Integer,Double> idmap = new HashMap<Integer,Double>();
		for(State st : this.dist.keySet()) {
			try {
				int id = 0;
				for(int i = 0; i < sizeSampleSpace; i++) {
					String outcome = st.getValue("input"+i);
					//System.out.println("  i = " + i);
					//System.out.println("  st.getValue = " + outcome);
					//System.out.println("  st.getValue = " + st.getValue("input"));
					id += bases[i] * stringToID(i, outcome, sampleSpace);
				}
				double prob = this.dist.get(st);
				idmap.put(id, prob);
				//System.out.println("  id = " + id + "  prob = " + prob);
				//System.out.println("  ------------------- ");
			} catch(Exception ex) {
				System.out.println("Error in reading elements of an input to calculate a projection of a state: " + ex);
				ex.printStackTrace();
				System.out.println("  The file does not follow a prior file (-prior) format.");
				System.exit(1);
			}
		}
		
		// enumerate the sample space and remove samples with non-zero probabilities
		int maxID = bases[sizeSampleSpace];
		//System.out.println("  maxID = " + maxID);
		for(int id = 0; id < maxID; id++) {
			if(idmap.containsKey(id) && idmap.get(id) != 0) {
				// non-zero probability
				if(verbose > 5) {
					System.out.println("  The sample with id = " + id + " exists in the channel matrix.");
				}
			} else {
				// zero probability
				// convert IDs to strings
				int marginalsID[] = new int[sizeSampleSpace];
				String outcomes[] = new String[sizeSampleSpace];
				int remainder = id;
				for(int i = jointNum - 1; i >= 0; i--) {
					marginalsID[i] = remainder / bases[i];
					outcomes[i] = IDToString(i, marginalsID[i], sampleSpace);
					remainder = remainder % bases[i];
				}
				
				// check wether the product of all marginals is non-zero
				boolean result = false;
				for(int i = 0; i < sizeSampleSpace; i++) {
					if(this.allMarginals[i].getProb(outcomes[i]) == 0) {
						result = true;
						break;
					}
				}
				if(!result) {
					if(idmap.containsKey(id)) {
						System.out.println("The joint input distribution is: ");
						this.printProbDist();
						System.out.println("while the marginals are:");
					} else {
						System.out.print("There is a sample with the zero joint probability: [");
						for(String outcome: outcomes) {
							System.out.print(" " + outcome);
						}
						System.out.println(" ] with id = " + id + ", while the marginals are:");
					}
					for(int i = 0; i < sizeSampleSpace; i++) {
						System.out.println("  marginal_" + i + "(" + outcomes[i] + ") = " + this.allMarginals[i].getProb(outcomes[i]));
					}
					System.out.println("Hence the joint input distribution is not jointly supported.");
					return result;
				}
			}
		}
		return true;
	}


	/**
	 * Returns a marginal probability distribution.
	 * 
	 * @param num the number s.t. X_num is the input domain
	 *        on which we take marginal distribution
	 * @return the num-th marginal probability distribution
	 */
	public ProbDist getMarginal(int num) {
		int jointNum = this.getNumJoint();
		//System.out.println("  ProbDist:701");
		if(num >= jointNum) {
	    	System.out.println("Error: " + num + "-th marginal probability is not defined.");
	    	System.out.println("  jointNum = " + jointNum);
			System.exit(1);
		} else if(jointNum == 1) {
			// copy the value of "input to the value of "input0" in the input distribution
			for(State jst : this.dist.keySet()) {
				String str = jst.getValue("input").replaceAll("\\(", " ").replaceAll("\\)", "").trim();
				jst.updateValue("input0", str);
			}
			return this;
		}

		// In the case all the marginals have been already calculated
		if(this.allMarginals != null && this.allMarginals[num] != null) {
			return this.allMarginals[num];
		}

		// initialize a hash map for the num-th marginal of the input distribution
		HashMap<State, Double> marginalProb = new HashMap<State, Double>();
		
		// read the joint input distribution and caluclate the num-th marginal
		for(State jst : this.dist.keySet()) {
			Pattern pattern = Pattern.compile("\\((.+?)\\)");
			String outcomeTuple = jst.getValue("input");
			Matcher matcher = pattern.matcher(outcomeTuple);
			if(matcher.find()) { // remove brackets from a joint input
				// Separate each element of the joint input
				String[] outcomes = matcher.group(1).split(",", 0);
				if(num < outcomes.length) {
					State st = new State();
					boolean found = false;
					for(State key : marginalProb.keySet()) {
				    	//System.out.println("  key = " + key.getValue("input"));
						if(key.getValue("input") != null && key.getValue("input").equals(outcomes[num].trim())) {
					    	//System.out.println("  outcomes[num] = " + outcomes[num].trim());
							found = true;
							st = key;
							break;
						}
					}
			    	//System.out.println("  found = " + found);
					if(found) {
						double prob = marginalProb.get(st) + this.dist.get(jst);
						marginalProb.put(st, prob);
					} else {
						st.updateValue("input", outcomes[num].trim());
						marginalProb.put(st, this.dist.get(jst));
					}
					jst.updateValue("input"+num, outcomes[num].trim());
					//System.out.println("   757:" + jst.getValue("input"+num));
			    	//System.out.println("   input" + num +" = " + outcomes[num]);
				} else {
			    	System.out.println("Error in reading elements of an input to calculate a marginal.");
			    	System.out.println("  The file does not follow a prior file (-prior) format.");
					System.exit(1);
				}
			} else {
		    	System.out.println("Error in reading elements of an input to calculate a marginal.");
		    	System.out.println("  The file does not follow a prior file (-prior) format.");
				System.exit(1);
			}
		}
		
		// return the marginal probability distribution
		return new ProbDist(marginalProb, true);
	}

	/**
	 * Returns the string that denotes a projection of a given joint state.
	 * 
	 * @param jst joint state
	 * @param numElements the number of elements that a state consists of
	 * @return the string denoting the numElements-th projection of st
	 */
	public String getProjectedState(State jst, int numElements) {
		String outcomeTuple = jst.getValue("input");

		// Case numJoint = 1
		if(this.getNumJoint() == 1) {
			return outcomeTuple.trim();
		}
		
		// Case numJoint > 1
		Pattern pattern = Pattern.compile("\\((.+?)\\)");
		Matcher matcher = pattern.matcher(outcomeTuple);
		try {
			if(matcher.find()) { // remove brackets from a joint input
				// Separate each element of the joint input
				String[] outcomes = matcher.group(1).split(",", 0);
				if(numElements < outcomes.length) {
					return outcomes[numElements].trim();
				}
			}
		} catch(Exception ex) {
			System.out.println("Error in reading elements of an input to calculate a projection of a state.");
			System.out.println("  The file does not follow a prior file (-prior) format.");
			System.exit(1);
		}
		System.out.println("Error in reading elements of an input to calculate a projection of a state.");
		System.out.println("  The file does not follow a prior file (-prior) format.");
		System.exit(1);
		return "";
	}

	
	/**
	 * Returns all the marginals of this probability distribution.
	 * 
	 * @return all the marginals of this probability distribution
	 */
	public ProbDist[] getAllMarginals() {
		int jointNum = this.getNumJoint();
		if(this.allMarginals != null) {
			return this.allMarginals;
		} else {
			ProbDist[] pds = new ProbDist[jointNum];
			for(int i = 0; i < jointNum; i++) {
				pds[i] = this.getMarginal(i);
				if(verbose > 5) {
					System.out.println("Marginal input distribution (" + i + ")");
					pds[i].printProbDist();
				}
			}
			allMarginals = pds;
			return pds;
		}
	}


	//////////////////////////////////////////////////////////////
	/**
	 * Print the probability of a state.
	 * 
	 * @param st state
	 */
	public void printProb(State st) {
		System.out.println("Pr" + st.stringState() + " = " + this.getProb(st));
	}

	/**
	 * Print the probability distribution.
	 */
	public void printProbDist() {
		System.out.println("{");
		for(State st : this.dist.keySet()) {
			if(st != null)
				System.out.println("  " + st.stringState() + " = " + this.dist.get(st));
		}
		System.out.println("}");
		if(verbose >= 5) {
			double sum = 0.0;
			for(State st : this.dist.keySet()) {
				if(st != null) {
					sum += this.getProb(st);
				}
			}
			System.out.println("Sum of probabilities: " + sum);
		}
	}

	/**
	 * Output the probability distribution to a file.
	 */
	public void printProbDist(File file) {
		try {
			PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(file)));
			for(State st : this.dist.keySet()) {
				if(st != null) {
					String str = st.getValue("input");
					pw.println("(" + this.dist.get(st) + ", " + str + ")");
				}
			}
			pw.close();
		} catch(FileNotFoundException ex) {
			System.out.println(" file not found " + ex);
		} catch(Exception ex) {
			System.out.println(" error " + ex);
		}
		if(verbose >= 5) {
			double sum = 0.0;
			for(State st : this.dist.keySet()) {
				if(st != null) {
					sum += this.getProb(st);
				}
			}
			System.out.println("Sum of probabilities: " + sum);
		}
	}
	
}
