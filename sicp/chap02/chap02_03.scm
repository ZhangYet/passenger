(define (memq item x)
  (cond ((null? x) #f)
	((eq? item (car x)) x)
	(else (memq item (cdr x)))))

;; exec 2.53
(list 'a 'b 'c)               ;; (a b c) 没有引号
(list (list 'george))         ;; ((george)) 也没有引号
(cdr '((x1 x2) (y1 y2)))      ;; ((y1 y2))
(cadr '((x1 x2) (y1 y2)))     ;; (y1 y2)
(pair? (car '(a short list))) ;; #f

(memq 'red '((red shoe) (blue socks))) ;; #f
(memq 'red '(red shoe blud sockes))    ;; (red shoe blud socks)

;; exec 2.54
(define (equal? x y)
  (if (or (null? x) (null? y))
      (and (null? x) (null? y))
      (and (eq? (car x) (car y))
	   (equal? (cdr x) (cdr y)))))

(equal? '(this is a list) '(this is a list))
(equal? '(this is a list) '(this (is a) list))

;;
