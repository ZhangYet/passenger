;; exec 2.26
(define x (list 1 2 3))
(define y (list 4 5 6))
(append x y) ; (1 2 3 4 5 6)
(cons x y)   ; ((1 2 3) 4 5 6)
(list x y)   ; ((1 2 3) (4 5 6))
(car x)      ; 1

;; exec 2.27
(define x (list (list 1 2) (list 3 4)))

(define (deep-reverse x)
  (cond ((null? x) '())
	((not (pair? x)) x)
	(else (append (deep-reverse (cdr x))
		      (list (deep-reverse (car x)))))))

(deep-reverse x)

;; exec 2.28
(define (fringe x)
  (cond ((null? x) '())
	((not (pair? x)) (list x))
	(else (append (fringe (car x))
		      (fringe (cdr x))))))

(fringe x)
(fringe (list x x))


;; exec 2.29
(define (make-mobile left right)
  (list left right))

(define (make-branch length structure)
  (list length structure))

(define (left-branch x)
  (car x))

(define (right-branch x)
  (cadr x))

(define (branch-length x)
  (car x))

(define (branch-structure x)
  (cadr x))

(define (branch-weight branch)
  (total-weight (branch-structure branch)))

(define (total-weight mobile)
  (if (not (pair? mobile))
      mobile                           ; 是重量
      (+ (branch-weight (left-branch mobile))
         (branch-weight (right-branch mobile)))))

(define m2 (make-mobile (make-branch 2 4) (make-branch 1 5)))
(define m1 (make-mobile (make-branch 5 3) (make-branch 3 m2)))

(total-weight m1)

;; notes
(define (scale-tree tree factor)
  (cond ((null? tree) '())
	((not (pair? tree)) (* tree factor))
	(else (cons (scale-tree (car tree) factor)
		    (scale-tree (cdr tree) factor)))))

(define tx (list 1 (list 2 (list 3 4) 5) (list 6 7)))
(scale-tree tx 10)

;; exec 2.30
(define (square-tree tree)
  (cond ((null? tree) '())
	((not (pair? tree)) (* tree tree))
	(else (cons (square-tree (car tree))
		    (square-tree (cdr tree))))))

(define (square-tree-map tree)
  (map (lambda (sub-tree)
	 (if (pair? sub-tree)
	     (square-tree-map sub-tree)
	     (* sub-tree sub-tree)))
       tree))

(square-tree tx)
(square-tree-map tx)

(define (tree-map op tree)
  (cond ((null? tree) '())
	((not (pair? tree)) (op tree))
	(else (cons (tree-map op (car tree))
		    (tree-map op (cdr tree))))))

;; exec 2.31
(define (square x) (* x x))
(define (square-tree-my-map tree)
  (tree-map square tree))

(square-tree-my-map tx)

;; exec 2.32

(define (subsets x)
  (if (null? x)
      (list x)
      (let ((rest (subsets (cdr x))))
	(append rest (map (lambda (s) (cons (car x) s)) rest)))))

(define x (list 1 2 3))
(subsets x)

(define (filter predicate sequence)
  (cond ((null? sequence) '())
	((predicate (car sequence))
	 (cons (car sequence)
	       (filter predicate (cdr sequence))))
	(else (filter predicate (cdr sequence)))))

(filter odd? (list 1 2 3 4 5))

(define (accumulate op initial sequence)
  (if (null? sequence)
      initial
      (op (car sequence)
	  (accumulate op initial (cdr sequence)))))

(accumulate + 0 (list 1 2 3 4 5 6))
