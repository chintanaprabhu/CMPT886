package ca.sfu.cmpt745.ex06.checker;

import static ca.sfu.cmpt745.ex06.checker.KittenAnalysis.State.TOP;
import static ca.sfu.cmpt745.ex06.checker.KittenAnalysis.State.BOTTOM;
import static ca.sfu.cmpt745.ex06.checker.KittenAnalysis.State.SLEEPING;
import static ca.sfu.cmpt745.ex06.checker.KittenAnalysis.State.EATING;
import static ca.sfu.cmpt745.ex06.checker.KittenAnalysis.State.PLAYING;
import static ca.sfu.cmpt745.ex06.checker.KittenAnalysis.State.PLOTTING;
import static ca.sfu.cmpt745.ex06.checker.KittenAnalysis.State.RUNNING;

import java.util.HashMap;
import java.util.Map;
import java.util.EnumSet;

import soot.BodyTransformer;
import soot.Body;
import soot.G;
import soot.Local;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.toolkits.graph.DirectedGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import soot.tagkit.LineNumberTag;

import soot.jimple.InvokeExpr;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.VirtualInvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.jimple.IfStmt;
import soot.jimple.GotoStmt;
import soot.jimple.ConditionExpr;
import soot.jimple.AssignStmt;
import soot.SootMethod;

public class KittenAnalysis extends ForwardFlowAnalysis<Unit, Map<Value, KittenAnalysis.State>> {
  public enum State {
    TOP,
    SLEEPING,
    EATING,
    PLAYING,
    PLOTTING,
    RUNNING,
    BOTTOM
  }

  private UnitGraph g;
  public KittenAnalysis (UnitGraph g) {
    super(g);
    this.g = g;
    doAnalysis();
  }

   @Override
   protected void merge(Map<Value, State> src1, Map<Value, State> src2, Map<Value, State> dest) {
      KittenErrorReporter err1 = new KittenErrorReporter();
      // merge the given 2 states based on the merge matrix (in README) 

      for (Value var1 : src1.keySet()) {
      State inVal1 = src1.get(var1);
      State inVal2 = src2.get(var1);
     if( inVal2 == null || inVal2 == BOTTOM)
	     dest.put(var1, inVal1);
     else {
      switch (inVal1) {
        case SLEEPING:
              switch(inVal2) {
                case SLEEPING:
                  dest.put(var1, SLEEPING);
		              break;
                case EATING:
                  dest.put(var1, EATING);
		              break;
                case PLAYING:
                  dest.put(var1, TOP);
                  break;
                case PLOTTING:
                  dest.put(var1, TOP);
                  break;
                case RUNNING:
                  dest.put(var1, RUNNING);
		              break;
              }
        break;
      case EATING:
          switch(inVal2) {
              case SLEEPING:
                dest.put(var1, SLEEPING);
		            break;
              case EATING:
                dest.put(var1, EATING);
		            break;
              case PLAYING:
                dest.put(var1, TOP);
                break;
              case PLOTTING:
                dest.put(var1, TOP);
                break;
              case RUNNING:
                dest.put(var1, RUNNING);
		            break;
            }
          break;
    case PLAYING:
          switch(inVal2) {
             case SLEEPING:
                  dest.put(var1, TOP);
                  break;
             case EATING:
                  dest.put(var1, EATING);
		              break;
             case PLAYING:
                  dest.put(var1, PLAYING);
		              break;
             case PLOTTING:
                  dest.put(var1, TOP);
                  break;
           case RUNNING:
                  dest.put(var1, RUNNING);
		              break;
          }
          break;
      case PLOTTING:
                  switch(inVal2) {
                  case SLEEPING:
                       dest.put(var1, SLEEPING);
		                   break;
                  case EATING:
                       dest.put(var1, EATING);
		                   break;
                  case PLAYING:
                       dest.put(var1, PLAYING);
		                   break;
                  case PLOTTING:
                       dest.put(var1, PLOTTING);
		                   break;
                  case RUNNING:
                       dest.put(var1, RUNNING);
		                   break;
               }
               break;
     case RUNNING:
          switch(inVal2) {
            case SLEEPING:
                dest.put(var1, TOP);
                break;
            case EATING:
                dest.put(var1, EATING);
		            break;
            case PLAYING:
                dest.put(var1, PLAYING);
		            break;
            case PLOTTING:
                dest.put(var1, PLOTTING);
		            break;
            case RUNNING:
                dest.put(var1, RUNNING);
		            break;
          }
          break;
      }
     }
   }
}


   @Override
   protected void copy(Map<Value, State> src, Map<Value, State> dest) {
	    dest.clear();
    	dest.putAll(src);
   }

   @Override
   protected Map<Value, State> entryInitialFlow() {
       // Returns the initial map of value and state for all the locals of type Kitten
       return newInitialFlow();
   }
   @Override
   protected Map<Value, State> newInitialFlow() {
       Map<Value, State> initMap = new HashMap<Value, State>();
	// every time an instance of kitten is seen in the graph, initialize it to BOTTOM state
       for ( ValueBox vb : g.getBody().getUseAndDefBoxes()) {
            Value val = vb.getValue();
            if(val instanceof SpecialInvokeExpr) {
		            SpecialInvokeExpr si = (SpecialInvokeExpr) val;
		            if(si.getMethod().getDeclaringClass().toString().equals("ca.sfu.cmpt745.ex06.kittens.Kitten")) {
		  	             Value v = (Value) si.getBase();
		  	             initMap.put(v, BOTTOM);
 		            }
 	          }
       }
       return initMap;
   }

@Override
   protected void flowThrough(Map<Value, State> src, Unit node, Map<Value, State> dest) {
       KittenErrorReporter err1 = new KittenErrorReporter();
       dest.putAll(src);
       if(node instanceof IfStmt){
          IfStmt gt = (IfStmt) node;
		if(gt.getConditionBox().toString().equals("ConditionExprBox(z0 == 0)")) {
		        node = gt.getTarget();
		}
       }
       if(node instanceof GotoStmt) {
	        GotoStmt gts = (GotoStmt) node;
	     }
       if(node instanceof AssignStmt) {
	        AssignStmt as = (AssignStmt) node;
	        if(!(as.getRightOp().toString().equals("new ca.sfu.cmpt745.ex06.kittens.Kitten"))) {
	          dest.put(as.getLeftOp(), dest.get(as.getRightOp()));
	        }
       }
       for(ValueBox vb : node.getUseAndDefBoxes()) {
            Value val = vb.getValue();
            if(val instanceof VirtualInvokeExpr) {
            VirtualInvokeExpr vi = (VirtualInvokeExpr) val;
  	    if(dest.containsKey(vi.getBase())) {
		//if this is the first flowthrough for any given flow, transition of the state of the kitten to SLEEPING
		if(dest.get(vi.getBase()).equals(BOTTOM))
		  dest.put(vi.getBase(), SLEEPING); 
	 	//perform the tranfer of the state based on the method invoked. 
		//If an invalid transfer found, print the error to STDOUT and terminate the analysis
                switch(vi.getMethod().getSubSignature().toString()) {
                  case "void pet()":
                    switch(dest.get(vi.getBase())) {
                      case RUNNING:
                          err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "SLEEPING", dest.get(vi.getBase()).toString());
                          System.exit(0);
                      case PLAYING:
                          err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "SLEEPING", dest.get(vi.getBase()).toString());
                          System.exit(0);
		                  case TOP:
			                    err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "SLEEPING", dest.get(vi.getBase()).toString());
			                    System.exit(0);
                     default:
                          dest.put(vi.getBase(), SLEEPING);
                    }
                  break;
                  case "void tease()":
                    switch(dest.get(vi.getBase())) {
                      case SLEEPING:
                          err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "PLAYING", dest.get(vi.getBase()).toString());
                          System.exit(0);
                      case EATING:
                          err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "PLAYING", dest.get(vi.getBase()).toString());
                          System.exit(0);
		      case TOP:
			  err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "PLAYING", dest.get(vi.getBase()).toString());
			  System.exit(0);
                      default:
                          dest.put(vi.getBase(), PLAYING);
                    }
                    break;
                  case "void ignore()":
                    switch(dest.get(vi.getBase())) {
                      case SLEEPING:
                        err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "PLOTTING", dest.get(vi.getBase()).toString());
                        System.exit(0);
                      case EATING:
                        err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "PLOTTING", dest.get(vi.getBase()).toString());
                        System.exit(0);
                      case PLAYING:
                        err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "PLOTTING", dest.get(vi.getBase()).toString());
                        System.exit(0);
		      case TOP:
	       		  err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "PLOTTING", dest.get(vi.getBase()).toString());
			  System.exit(0);
                      default:
                        dest.put(vi.getBase(), PLOTTING);
                    }
                    break;
                  case "void feed()":
		    switch(dest.get(vi.getBase())) {
			case TOP:
	     		  err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "EATING", dest.get(vi.getBase()).toString());
			  System.exit(0);
			default:
	                    dest.put(vi.getBase(), EATING);
		    }
                    break;
                  case "void scare()":
		    switch(dest.get(vi.getBase())) {
			case TOP:
	  		  err1.reportError(vi.getBase().toString(), Integer.parseInt(node.getTag("LineNumberTag").toString()), "RUNNING", dest.get(vi.getBase()).toString());
			  System.exit(0);
			default:
	                    dest.put(vi.getBase(), RUNNING);
		    }
                    break;
                }
              }
        }
       }
   }
}

