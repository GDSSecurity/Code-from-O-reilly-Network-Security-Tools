package net.sourceforge.pmd.rules.web.security;

import net.sourceforge.pmd.AbstractRule;
import net.sourceforge.pmd.ast.*;
import net.sourceforge.pmd.RuleContext;
import org.apache.regexp.*;
import java.util.*;
import java.text.MessageFormat;

public class DynSqlSelectStmts extends AbstractRule {

  private static boolean debug = true;

  private static final String PATTERN = "select.+from";

  private String currMethName;
  private int currMethXsVis;
  private Map currMethParams;
  private String currMethSymptomCode;
  private List currMethExprsToChase;
  private List currMethVarsChased;

  private void init ( )
  {
    currMethName = "";
    currMethXsVis = 0;
    currMethParams = new HashMap( );
    currMethSymptomCode = "";
    currMethExprsToChase = new ArrayList( );
    currMethVarsChased = new LinkedList( );
  }

  public void setDebug (boolean x)
  {
    debug = x;
  }

  public void printDebug (String str)
  {
    if (debug)
      System.out.print(str + "\n");
  }
  public Object visit(ASTCompilationUnit node, Object data)
  {
    getInfo(node);
    printDebug("Rule: " + this.getName( ) + "\n\n");
    return super.visit(node,data);
  }
  public Object visit(ASTClassBodyDeclaration node, Object data)
  {
    getInfo(node);

    if (!(node.jjtGetChild(0) instanceof ASTMethodDeclaration))
    {
      return null;
    }

    this.init( );

        return super.visit(node,data);
  }

  public Object visit(ASTMethodDeclaration node, Object data)
  {
      getInfo(node);
      currMethXsVis++;
      printDebug ("Number of visits to " + node.getClass( ).getName( ) + ": " + currMethXsVis +
        "\n");

      if (currMethXsVis == 1)
      {
        currMethName = ((ASTMethodDeclarator)node.jjtGetChild(1)).getImage( );
        printDebug ("Current Method: " + currMethName + "\n");
      }

      else
      {
        List locVarDecList = (ArrayList)node.findChildrenOfType
           (ASTLocalVariableDeclaration.class);
        for (Iterator j = locVarDecList.iterator( ); j.hasNext( );)
        {
          if (currMethExprsToChase.size( ) > 0)
            chkLocVarsForUCI((ASTLocalVariableDeclaration)j.next( ),data);
          else
            break;
        }

        return null;
      }

      return super.visit(node,data);
    }

  public Object visit(ASTMethodDeclarator node, Object data)
  {
    getInfo(node);

    if (currMethXsVis == 1)
    {
      getCurrMethParams(node);
      printCurrMethParams( );
    }
    return super.visit(node,data);
  }


  public Object visit(ASTAdditiveExpression node, Object data)
  {

    getInfo(node);

    List literals = node.findChildrenOfType(ASTLiteral.class);

      for (Iterator l = literals.iterator( ); l.hasNext( );)
      {
        ASTLiteral astLiteral = (ASTLiteral)l.next( );
        String literal = astLiteral.getImage( );
        printDebug("Literal: " + literal + "\n");

        if (literal != null && isMatch(literal))
        {
          RuleContext ctx = (RuleContext) data;
          currMethSymptomCode = literal;
          String msg = MessageFormat.format(getMessage( ), new Object[]
            {"SQL select statement detected: " + currMethSymptomCode});
          printDebug("Report message: " + msg + "\n");
          ctx.getReport( ).addRuleViolation(createRuleViolation
            (ctx, astLiteral.getBeginLine( ), msg));

          // Look for expression(s) other than literals appended to SQL
          List names = (ArrayList) node.findChildrenOfType(ASTName.class);
          if ( names.size( ) > 0 )
          {
            // Check whether the appended expression(s) are UCI
            List uci = chkForUCI(names);
            if ( ! uci.isEmpty( ) )
            {
              for (Iterator i = uci.iterator( );i.hasNext( );)
              {
                ASTName n = (ASTName)i.next( );
                msg = MessageFormat.format(getMessage( ), new Object[]
                 {"SQL select statement detected with UCI: " + n.getImage( )});
                printDebug("Report message: " + msg + "\n");
                ctx.getReport( ).addRuleViolation
                  (createRuleViolation(ctx, astLiteral.getBeginLine( ), msg));
              }
            }

            /*
             * Expression(s) appended to SQL are not immediate source of UCI
             * Re-visit method declaration to begin logic for finding initializer of UCI
             */

            else
            {
              printDebug ("Expression(s) appended to SQL are not immediate source of 
                UCI\n\n");
              currMethExprsToChase = new ArrayList(names);
              printDebug("*** Begin expression chasing routine *** \n\n");
              visit( (ASTMethodDeclaration) node.getFirstParentOfType
                  (ASTMethodDeclaration.class),data);
              printDebug("... Exiting from visit - ASTAdditiveExpression ...\n");
              printDebug("*** Returning from expression chasing routine ... 
                        Done with this ASTAdditiveExpression ... any more?? ***\n\n");
              this.init( );
            }
          }

        }
      }

      return super.visit(node,data);
  }

  public void chkLocVarsForUCI(ASTLocalVariableDeclaration node, Object data)
  {
    getInfo(node);

    printCurrMethExprsToChase( );

    ASTVariableDeclarator varDec = (ASTVariableDeclarator)node.jjtGetChild(1);
    String varName = ((ASTVariableDeclaratorId)varDec.jjtGetChild(0)).getImage( );
    printDebug("Local Variable Name: " + varName + "\n");

    ASTVariableInitializer varInit = (ASTVariableInitializer)varDec.jjtGetChild(1);

    ASTName initExp = null;
    if (varInit.findChildrenOfType(ASTName.class).size( ) 
        > 0 && varInit.findChildrenOfType(ASTName.class).get(0) instanceof ASTName)
    {
      initExp = (ASTName) varInit.findChildrenOfType(ASTName.class).get(0);
      printDebug("Local Variable Initializer: " + initExp.getImage( ) + "\n");
    } else {
      return;
    }

    boolean chase = false;
    boolean srcOfUCI = false;
    int cnt = 0;
    int index = 0;
    for (Iterator i = currMethExprsToChase.iterator( ); i.hasNext( );)
    {
      ASTName currNode = (ASTName)i.next( );
      printDebug("Checking: " + currNode.getImage( ) + "\n");
      if ( currNode.getImage( ).matches(varName) )
      {
        printDebug("Loc var: " + varName + " matches '" + currNode.getImage( ) + "', which is
           an expression we are currently chasing\n");
        ((LinkedList)currMethVarsChased).addLast(currNode.getImage( ));
        String uci = chkForUCI(initExp);
        if (uci != null)
        {
          printDebug("Initializing expression: " + initExp.getImage( ) + " is a source of UCI:
            [" + uci + "]\n");
          srcOfUCI = true;
          index = cnt;
          break;
        }
        else
        {
          printDebug("Need to chase the local var initializer: '" 
                    + initExp.getImage( ) + "'\n");
          chase = true;
          index = cnt;
          break;
        }
      }
      cnt++;
    }

    if (srcOfUCI)
    {
      ((ArrayList)currMethExprsToChase).remove(index);

      /* Add uci - Appending the ASTLiteral node with the expectation that the source
       * of uci is from HttpServletRequest ( i.e. something like req.getParameter("id") ).
       * This will not always be the case, and so will have to make this 
         a little more generic.
       */

      ASTLiteral lit = (ASTLiteral)node.findChildrenOfType(ASTLiteral.class).get(0);
      ((LinkedList)currMethVarsChased).addLast(initExp.getImage( ) 
        + "(" + lit.getImage( ) + ")");
      String uciChased = printCurrMethVarsChased( );

      RuleContext ctx = (RuleContext) data;
      String msg = MessageFormat.format(getMessage( ), new Object[]
        {"SQL select statement detected with UCI: " + uciChased });
      printDebug("Report message: " + msg + "\n");
      ctx.getReport( ).addRuleViolation(createRuleViolation(ctx, lit.getBeginLine( ), msg));
      currMethVarsChased = new LinkedList( );

    } else if (chase)
    {
      ((ArrayList)currMethExprsToChase).remove(index);

      ((ArrayList)currMethExprsToChase).add(index,initExp);

      visit( (ASTMethodDeclaration)node.getFirstParentOfType
        (ASTMethodDeclaration.class),data);
      printDebug("... Exiting from chkLocVarsForUCI\n");
    }


  }

  public void getInfo (SimpleNode node)
    {
    printDebug ("\n====================");

    Object o = node;
    Class c = o.getClass( );
    printDebug ("Class Name: " + c.getName( ));

    int begLine = node.getBeginLine( );
    if (begLine != 0)
    {
      printDebug("Line #: " + begLine);
    }

    }

  private void getCurrMethParams (ASTMethodDeclarator node)
  {
   if (node.getParameterCount( ) > 0)
   {
    List methodParams = node.findChildrenOfType(ASTFormalParameter.class);
    for (Iterator i = methodParams.iterator( );i.hasNext( );)
    {
     ASTFormalParameter p = (ASTFormalParameter)i.next( );
     ASTName pType =   (ASTName)p.jjtGetChild(0).jjtGetChild(0);
     ASTVariableDeclaratorId pName =   (ASTVariableDeclaratorId)p.jjtGetChild(1);
     currMethParams.put(pName.getImage( ),pType.getImage( ));
    }
   }
  }

  private void printCurrMethParams ( )
  {
    for (Iterator i = currMethParams.keySet( ).iterator( ); i.hasNext( );)
    {
        String key = (String)i.next( );
        String value = (String)currMethParams.get(key);
        printDebug ("Param Name: " + key + ", Param Type: " + value);
    }
  }

  private void printCurrMethExprsToChase ( )
  {
    printDebug ("Chasing the following expressions:\n");
    for (Iterator i = currMethExprsToChase.iterator( ); i.hasNext( );)
    {
        String value = ((ASTName)i.next( )).getImage( );
        printDebug (value + "\n");
    }
  }

  private String printCurrMethVarsChased ( )
  {
    printDebug ("Chased the following variables to UCI: " + currMethVarsChased.size( ) 
+ "\n");
    String str = "";
    for (Iterator i = currMethVarsChased.iterator( ); i.hasNext( );)
    {
        String value = (String)i.next( );
        if (i.hasNext( ))
        {
          str = str + (value + " --> ");
        }
        else
        {
          str = str + value;
        }
    }

    printDebug(str + "\n");
    return str;
  }

  private boolean isMatch(String literal)
  {
   boolean match = false;

   RE sql = new RE(PATTERN);

   sql.setMatchFlags(RE.MATCH_CASEINDEPENDENT);

   return sql.match(literal);

  }

  private List chkForUCI(List names)
  {
   List uci = new ArrayList( );
   for (Iterator i = names.iterator( );i.hasNext( );)
   {
    ASTName name = (ASTName)i.next( );
    for (Iterator j = currMethParams.keySet( ).iterator( ); j.hasNext( );)
    {
     String currMethParam = (String)j.next( );
     RE re = new RE (currMethParam);
     if ( re.match(name.getImage( )) )
     {
      uci.add(name);
      break;
     }
    }
   }
   return uci;
  }

    private String chkForUCI(ASTName name)
    {
      for (Iterator j = currMethParams.keySet( ).iterator( );                     
  j.hasNext( );)
      {
       String currMethParam = (String)j.next( );
       RE re = new RE (currMethParam);
       if ( re.match(name.getImage( )) )
       {
        return currMethParam;
       }
      }
      return null;
     }
}
