//! Visitor traits for traversing expressions.
//!
//! The `Visitor` trait provides a flexible way to traverse and analyze
//! GitHub Actions expressions. It follows the visitor pattern, allowing
//! you to define custom behavior for each expression type while automatically
//! handling the recursive traversal of sub-expressions.
//!
//! ## Example Usage
//!
//! ```rust
//! use github_actions_expressions::{Expr, visitor::{Visitor, Visitable}};
//! use github_actions_expressions::Literal;
//!
//! // Create a custom visitor that finds all string literals
//! struct StringFinder {
//!     strings: Vec<String>,
//! }
//!
//! impl StringFinder {
//!     fn new() -> Self {
//!         Self { strings: Vec::new() }
//!     }
//! }
//!
//! impl<'src> Visitor<'src> for StringFinder {
//!     fn visit_literal(&mut self, lit: &Literal<'src>) {
//!         if let Literal::String(s) = lit {
//!             self.strings.push(s.to_string());
//!         }
//!         self.super_literal(lit);
//!     }
//! }
//!
//! // Parse an expression and find all strings
//! let expr = Expr::parse("format('Hello, {0}!', github.actor)").unwrap();
//! let mut finder = StringFinder::new();
//! expr.accept(&mut finder);
//!
//! assert_eq!(finder.strings, vec!["Hello, {0}!"]);
//! ```

use crate::{BinOp, Expr, Function, Identifier, Literal, SpannedExpr, UnOp, context::Context};

/// A visitor trait for traversing GitHub Actions expressions.
///
/// This trait provides methods for visiting each variant of `Expr` and its
/// sub-components. The default implementations call the corresponding "super"
/// methods, which handle the recursive traversal automatically.
///
/// Users can override specific visit methods to customize behavior for
/// particular expression types while still benefiting from automatic
/// traversal of sub-expressions.
pub trait Visitor<'src> {
    /// Visit an expression.
    ///
    /// This is the main entry point for visiting expressions.
    fn visit_expr(&mut self, expr: &Expr<'src>) {
        self.super_expr(expr);
    }

    /// Visit a literal value.
    fn visit_literal(&mut self, lit: &Literal<'src>) {
        self.super_literal(lit);
    }

    /// Visit a star pattern (`*`).
    fn visit_star(&mut self) {
        self.super_star();
    }

    /// Visit a function call.
    fn visit_call(&mut self, func: &Function<'src>, args: &[&Expr<'src>]) {
        self.super_call(func, args);
    }

    /// Visit an identifier.
    fn visit_identifier(&mut self, ident: &Identifier<'src>) {
        self.super_identifier(ident);
    }

    /// Visit an index expression.
    fn visit_index(&mut self, expr: &Expr<'src>) {
        self.super_index(expr);
    }

    /// Visit a context reference.
    fn visit_context(&mut self, ctx: &Context<'src>) {
        self.super_context(ctx);
    }

    /// Visit a binary operation.
    fn visit_binop(&mut self, lhs: &Expr<'src>, op: &BinOp, rhs: &Expr<'src>) {
        self.super_binop(lhs, op, rhs);
    }

    /// Visit a unary operation.
    fn visit_unop(&mut self, op: &UnOp, expr: &Expr<'src>) {
        self.super_unop(op, expr);
    }

    // Super methods handle the default traversal logic and are not meant to be overridden.

    /// Default traversal for expressions.
    ///
    /// Dispatches to the appropriate visit method based on the expression variant.
    fn super_expr(&mut self, expr: &Expr<'src>) {
        match expr {
            Expr::Literal(lit) => self.visit_literal(lit),
            Expr::Star => self.visit_star(),
            Expr::Call { func, args } => {
                // Convert SpannedExpr args to Expr args
                let expr_args: Vec<&Expr<'src>> = args.iter().map(|arg| &arg.inner).collect();
                self.visit_call(func, &expr_args[..]);
            }
            Expr::Identifier(ident) => self.visit_identifier(ident),
            Expr::Index(expr) => self.visit_index(&expr.inner),
            Expr::Context(ctx) => self.visit_context(ctx),
            Expr::BinOp { lhs, op, rhs } => self.visit_binop(&lhs.inner, op, &rhs.inner),
            Expr::UnOp { op, expr } => self.visit_unop(op, &expr.inner),
        }
    }

    /// Terminal for `visit_literal`.
    fn super_literal(&mut self, _lit: &Literal<'src>) {}

    /// Terminal for `visit_star`.
    fn super_star(&mut self) {}

    /// Default traversal for function calls.
    ///
    /// Visits all arguments.
    fn super_call(&mut self, _func: &Function<'src>, args: &[&Expr<'src>]) {
        for arg in args {
            self.visit_expr(arg);
        }
    }

    /// Terminal for `visit_identifier`.
    fn super_identifier(&mut self, _ident: &Identifier<'src>) {}

    /// Default traversal for index expressions.
    ///
    /// Visits the inner expression.
    fn super_index(&mut self, expr: &Expr<'src>) {
        self.visit_expr(expr);
    }

    /// Default traversal for context references.
    ///
    /// Visits all parts of the context.
    fn super_context(&mut self, ctx: &Context<'src>) {
        for part in &ctx.parts {
            self.visit_expr(&part.inner);
        }
    }

    /// Default traversal for binary operations.
    ///
    /// Visits both operands.
    fn super_binop(&mut self, lhs: &Expr<'src>, _op: &BinOp, rhs: &Expr<'src>) {
        self.visit_expr(lhs);
        self.visit_expr(rhs);
    }

    /// Default traversal for unary operations.
    ///
    /// Visits the operand.
    fn super_unop(&mut self, _op: &UnOp, expr: &Expr<'src>) {
        self.visit_expr(expr);
    }
}

/// Extension trait to add visitor functionality to expressions.
pub trait Visitable<'src> {
    /// Accept a visitor and traverse this expression.
    fn accept<V: Visitor<'src>>(&self, visitor: &mut V);
}

impl<'src> Visitable<'src> for SpannedExpr<'src> {
    fn accept<V: Visitor<'src>>(&self, visitor: &mut V) {
        visitor.visit_expr(&self.inner);
    }
}

impl<'src> Visitable<'src> for Expr<'src> {
    fn accept<V: Visitor<'src>>(&self, visitor: &mut V) {
        // We can dispatch directly to visit_expr
        visitor.visit_expr(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Expr;

    /// Example visitor that counts different types of expressions.
    #[derive(Default)]
    struct ExpressionCounter {
        literals: usize,
        identifiers: usize,
        function_calls: usize,
        binary_ops: usize,
        unary_ops: usize,
        contexts: usize,
        stars: usize,
        indices: usize,
    }

    impl<'src> Visitor<'src> for ExpressionCounter {
        fn visit_literal(&mut self, lit: &Literal<'src>) {
            self.literals += 1;
            self.super_literal(lit);
        }

        fn visit_identifier(&mut self, ident: &Identifier<'src>) {
            self.identifiers += 1;
            self.super_identifier(ident);
        }

        fn visit_call(&mut self, func: &Function<'src>, args: &[&Expr<'src>]) {
            self.function_calls += 1;
            self.super_call(func, args);
        }

        fn visit_binop(&mut self, lhs: &Expr<'src>, op: &BinOp, rhs: &Expr<'src>) {
            self.binary_ops += 1;
            self.super_binop(lhs, op, rhs);
        }

        fn visit_unop(&mut self, op: &UnOp, expr: &Expr<'src>) {
            self.unary_ops += 1;
            self.super_unop(op, expr);
        }

        fn visit_context(&mut self, ctx: &Context<'src>) {
            self.contexts += 1;
            self.super_context(ctx);
        }

        fn visit_star(&mut self) {
            self.stars += 1;
            self.super_star();
        }

        fn visit_index(&mut self, expr: &Expr<'src>) {
            self.indices += 1;
            self.super_index(expr);
        }
    }

    #[test]
    fn test_visitor_counting() {
        let expr = Expr::parse("foo.bar[1] && !baz || format('hello', github.actor)").unwrap();
        let mut counter = ExpressionCounter::default();
        expr.accept(&mut counter);

        // The expression contains:
        // - 2 literals: 1, 'hello'
        // - 5 identifiers: foo, bar, baz, github, actor
        // - 1 function call: format
        // - 2 binary ops: &&, ||
        // - 1 unary op: !
        // - 3 contexts: foo.bar[1], baz, github.actor (single identifiers are also contexts)
        // - 1 index: [1]
        assert_eq!(counter.literals, 2);
        assert_eq!(counter.identifiers, 5);
        assert_eq!(counter.function_calls, 1);
        assert_eq!(counter.binary_ops, 2);
        assert_eq!(counter.unary_ops, 1);
        assert_eq!(counter.contexts, 3);
        assert_eq!(counter.indices, 1);
    }

    /// Example visitor that counts context references.
    #[derive(Default)]
    struct ContextCounter {
        contexts: usize,
    }

    impl<'src> Visitor<'src> for ContextCounter {
        fn visit_context(&mut self, ctx: &Context<'src>) {
            self.contexts += 1;
            self.super_context(ctx);
        }
    }

    #[test]
    fn test_context_counter() {
        let expr = Expr::parse("foo.bar && github.event.name || inputs.value").unwrap();
        let mut counter = ContextCounter::default();
        expr.accept(&mut counter);

        assert_eq!(counter.contexts, 3);
        // The expression contains three contexts: foo.bar, github.event.name, inputs.value
    }
}
